//! Physical extent maps for CoW-aware content hashing.
//!
//! On Linux, `FS_IOC_FIEMAP` reports where a file's logical ranges physically
//! live. Two files that share a physical extent on a copy-on-write filesystem
//! hold identical bytes there: a write to either side forces a private copy
//! first. The chunked manifest hasher ([`crate::manifest`]) uses this as
//! *proof* that a chunk of a child file equals the same logical chunk of its
//! parent's stored bytes, letting the child reuse the parent's chunk digest
//! without rereading them.
//!
//! Every decision fails safe toward reading: an extent the kernel cannot
//! prove shared (unknown physical address, inline or encoded data, encrypted
//! data, delalloc'd writes) and any host without FIEMAP (non-Linux, or a
//! non-reflink filesystem) falls back to reading and hashing the bytes —
//! exactly the unoptimized cost. Regions the filesystem guarantees read as
//! zeros (true holes and unwritten preallocation) are never read at all:
//! their digest is the digest of the zero bytes a read would have returned.

use std::io;
use std::path::Path;

// `fe_flags` values from <linux/fiemap.h>. They are the Linux UAPI, and the
// classification below is compiled (and tested) on every host so the chunk
// planner stays platform-independent.
const FIEMAP_EXTENT_UNKNOWN: u32 = 0x2;
const FIEMAP_EXTENT_DELALLOC: u32 = 0x4;
const FIEMAP_EXTENT_ENCODED: u32 = 0x8;
const FIEMAP_EXTENT_DATA_ENCRYPTED: u32 = 0x80;
const FIEMAP_EXTENT_NOT_ALIGNED: u32 = 0x100;
const FIEMAP_EXTENT_DATA_INLINE: u32 = 0x200;
const FIEMAP_EXTENT_DATA_TAIL: u32 = 0x400;
const FIEMAP_EXTENT_UNWRITTEN: u32 = 0x800;
const FIEMAP_EXTENT_SHARED: u32 = 0x2000;

/// What one file region provably contains, for hashing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtentKind {
    /// Stored data at a known physical location. `shared` is the kernel's
    /// promise that another file references the same blocks under CoW
    /// semantics, so reading either file returns the same bytes.
    Data { physical: u64, shared: bool },
    /// Provably reads as zeros: a true hole or unwritten preallocation.
    Zero,
    /// Present but unusable as identity proof (unknown physical location,
    /// inline/encoded/encrypted payload, or dirty not-yet-allocated data).
    Opaque,
}

/// One contiguous logical run of a file, as the kernel reported it.
/// Classification is deferred to [`Extent::kind`] so every platform compiles
/// the same planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Extent {
    pub logical: u64,
    pub physical: u64,
    pub len: u64,
    pub flags: u32,
}

impl Extent {
    /// Classify the raw extent. Conservative: any flag that makes the
    /// physical address or the byte content unusable as identity proof
    /// (unknown location, inline/encoded/encrypted payload, dirty
    /// not-yet-allocated data, misalignment) yields [`ExtentKind::Opaque`].
    fn kind(&self) -> ExtentKind {
        if self.flags
            & (FIEMAP_EXTENT_UNKNOWN
                | FIEMAP_EXTENT_DELALLOC
                | FIEMAP_EXTENT_ENCODED
                | FIEMAP_EXTENT_DATA_ENCRYPTED
                | FIEMAP_EXTENT_NOT_ALIGNED
                | FIEMAP_EXTENT_DATA_INLINE
                | FIEMAP_EXTENT_DATA_TAIL)
            != 0
        {
            return ExtentKind::Opaque;
        }
        if self.flags & FIEMAP_EXTENT_UNWRITTEN != 0 {
            return ExtentKind::Zero;
        }
        ExtentKind::Data {
            physical: self.physical,
            shared: self.flags & FIEMAP_EXTENT_SHARED != 0,
        }
    }
}

/// A whole file's extent map: length plus its sorted, non-overlapping
/// extents. Logical ranges covered by no extent are true holes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileExtentMap {
    pub len: u64,
    pub extents: Vec<Extent>,
}

/// How one chunk's digest is obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChunkPlan {
    /// The chunk provably reads as zeros; hash the zero bytes without I/O.
    Zero,
    /// Every byte of the chunk is CoW-shared with the same logical range of
    /// the base file, so the base manifest's chunk digest applies unchanged.
    ReuseBase,
    /// No proof available; read and hash the chunk's bytes.
    Read,
}

/// Split `[lo, hi)` into the file's extent coverage: one segment per maximal
/// sub-range of uniform kind. Ranges with no extent are holes (`Zero`).
fn segments(map: &FileExtentMap, lo: u64, hi: u64) -> Vec<(u64, u64, ExtentKind)> {
    let mut out = Vec::new();
    let mut pos = lo;
    for extent in &map.extents {
        if extent.logical >= hi {
            break;
        }
        let end = extent.logical.saturating_add(extent.len);
        if end <= pos {
            continue;
        }
        let seg_start = pos.max(extent.logical);
        if seg_start > pos {
            out.push((pos, seg_start, ExtentKind::Zero));
        }
        let seg_end = end.min(hi);
        out.push((seg_start, seg_end, extent.kind()));
        pos = seg_end;
    }
    if pos < hi {
        out.push((pos, hi, ExtentKind::Zero));
    }
    out
}

/// Whether `base` stores every byte of the child's `data` segments at the
/// same physical locations. Physical equality on a CoW filesystem is byte
/// equality: neither side can have diverged without the kernel first copying
/// the blocks. The base's segments may be merged differently than the
/// child's; the comparison is per logical range, not per struct.
fn base_matches(base: &FileExtentMap, data: &[(u64, u64, u64)]) -> bool {
    data.iter().all(|&(seg_lo, seg_hi, physical)| {
        let mut covered = seg_lo;
        let mut ok = true;
        for extent in &base.extents {
            let end = extent.logical.saturating_add(extent.len);
            if end <= covered || extent.logical >= seg_hi {
                continue;
            }
            // The base extent must be stored data whose physical address
            // agrees with the child's at the same logical offset.
            let ExtentKind::Data { physical: p, .. } = extent.kind() else {
                ok = false;
                break;
            };
            if p + (covered - extent.logical) != physical + (covered - seg_lo) {
                ok = false;
                break;
            }
            covered = covered.max(end.min(seg_hi));
        }
        ok && covered >= seg_hi
    })
}

/// Plan how to obtain every chunk digest of a file of `map.len` bytes,
/// optionally reusing a base manifest's digests where the base file's extent
/// map proves byte identity. Pure: the FIEMAP read happens once per file in
/// the caller, so this stays unit-testable without a reflink filesystem.
pub(crate) fn plan_file_chunks(
    map: &FileExtentMap,
    chunk_len: u64,
    base: Option<&FileExtentMap>,
) -> Vec<ChunkPlan> {
    if chunk_len == 0 || map.len == 0 {
        return Vec::new();
    }
    let chunk_count = map.len.div_ceil(chunk_len);
    let mut plans = Vec::with_capacity(usize::try_from(chunk_count).unwrap_or(usize::MAX));
    for index in 0..chunk_count {
        let lo = index * chunk_len;
        let hi = (lo + chunk_len).min(map.len);
        let segs = segments(map, lo, hi);
        if segs.iter().all(|&(_, _, kind)| kind == ExtentKind::Zero) {
            plans.push(ChunkPlan::Zero);
            continue;
        }
        let mut data = Vec::with_capacity(segs.len());
        let mut all_shared = true;
        for &(seg_lo, seg_hi, kind) in &segs {
            match kind {
                ExtentKind::Data { physical, shared } => {
                    all_shared &= shared;
                    data.push((seg_lo, seg_hi, physical));
                }
                // A hole/Opaque region inside the chunk: a hole would make
                // the chunk all-zero only if every region were a hole
                // (handled above); anything else must be read.
                _ => {
                    plans.push(ChunkPlan::Read);
                    break;
                }
            }
        }
        if data.len() != segs.len() {
            continue;
        }
        match base {
            Some(base) if all_shared && base_matches(base, &data) => {
                plans.push(ChunkPlan::ReuseBase);
            }
            _ => plans.push(ChunkPlan::Read),
        }
    }
    plans
}

/// Read `path`'s extent map from the kernel. Unsupported off Linux; callers
/// fall back to reading every byte.
#[cfg(target_os = "linux")]
pub(crate) fn extent_map(path: &Path) -> io::Result<FileExtentMap> {
    linux::extent_map(path)
}

/// Non-Linux hosts have no FIEMAP: no chunk of any file is ever reused or
/// skipped here, so hashing behaves exactly as an unoptimized full read.
#[cfg(not(target_os = "linux"))]
pub(crate) fn extent_map(_path: &Path) -> io::Result<FileExtentMap> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "extent maps require Linux FIEMAP",
    ))
}

#[cfg(target_os = "linux")]
mod linux {
    #![allow(unsafe_code)]

    use super::{Extent, FileExtentMap};
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    // <linux/fs.h>: _IOWR('f', 11, struct fiemap), encoded the same way
    // across the architectures this crate targets (x86_64, aarch64).
    const FS_IOC_FIEMAP: libc::c_ulong = 0xC020_660B;
    // <linux/fiemap.h>.
    const FIEMAP_FLAG_SYNC: u32 = 0x1;
    const FIEMAP_EXTENT_LAST: u32 = 0x1;
    const EXTENTS_PER_QUERY: usize = 64;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FiemapExtent {
        fe_logical: u64,
        fe_physical: u64,
        fe_length: u64,
        fe_reserved64: [u64; 2],
        fe_flags: u32,
        fe_reserved: [u32; 3],
    }

    #[repr(C)]
    struct Fiemap {
        fm_start: u64,
        fm_length: u64,
        fm_flags: u32,
        fm_mapped_extents: u32,
        fm_extent_count: u32,
        fm_reserved: u32,
    }

    #[repr(C)]
    struct FiemapBuf {
        header: Fiemap,
        extents: [FiemapExtent; EXTENTS_PER_QUERY],
    }

    fn query(file: &File, start: u64) -> io::Result<(Vec<Extent>, bool)> {
        let mut buf = Box::new(FiemapBuf {
            header: Fiemap {
                fm_start: start,
                fm_length: u64::MAX,
                fm_flags: FIEMAP_FLAG_SYNC,
                fm_mapped_extents: 0,
                fm_extent_count: EXTENTS_PER_QUERY as u32,
                fm_reserved: 0,
            },
            extents: [FiemapExtent {
                fe_logical: 0,
                fe_physical: 0,
                fe_length: 0,
                fe_reserved64: [0; 2],
                fe_flags: 0,
                fe_reserved: [0; 3],
            }; EXTENTS_PER_QUERY],
        });
        // SAFETY: `buf` is a valid, exclusively owned, correctly sized fiemap
        // buffer that outlives the ioctl; the fd is open for the call.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), FS_IOC_FIEMAP, &mut *buf) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) => Err(
                    io::Error::new(io::ErrorKind::Unsupported, "FIEMAP is unavailable"),
                ),
                _ => Err(error),
            };
        }
        let mapped = usize::try_from(buf.header.fm_mapped_extents).unwrap_or(0);
        let mut extents = Vec::with_capacity(mapped);
        let mut last = false;
        for raw in buf.extents.iter().take(mapped) {
            extents.push(Extent {
                logical: raw.fe_logical,
                physical: raw.fe_physical,
                len: raw.fe_length,
                flags: raw.fe_flags,
            });
            if raw.fe_flags & FIEMAP_EXTENT_LAST != 0 {
                last = true;
            }
        }
        Ok((extents, last))
    }

    pub(super) fn extent_map(path: &Path) -> io::Result<FileExtentMap> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let mut extents = Vec::new();
        let mut start = 0;
        loop {
            let (mut batch, last) = query(&file, start)?;
            if batch.is_empty() {
                break;
            }
            start = batch
                .iter()
                .map(|e| e.logical.saturating_add(e.len))
                .max()
                .unwrap_or(start);
            extents.append(&mut batch);
            if last || start >= len {
                break;
            }
        }
        extents.sort_by_key(|e| e.logical);
        Ok(FileExtentMap { len, extents })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(logical: u64, len: u64, physical: u64, shared: bool) -> Extent {
        Extent {
            logical,
            physical,
            len,
            flags: if shared { FIEMAP_EXTENT_SHARED } else { 0 },
        }
    }

    fn zero(logical: u64, len: u64) -> Extent {
        Extent {
            logical,
            physical: 0,
            len,
            flags: FIEMAP_EXTENT_UNWRITTEN,
        }
    }

    fn opaque(logical: u64, len: u64) -> Extent {
        Extent {
            logical,
            physical: 0,
            len,
            flags: FIEMAP_EXTENT_UNKNOWN,
        }
    }

    fn map(len: u64, extents: Vec<Extent>) -> FileExtentMap {
        FileExtentMap { len, extents }
    }

    #[test]
    fn an_all_hole_file_plans_every_chunk_zero() {
        let m = map(3 * 1024 * 1024, vec![]);
        let plans = plan_file_chunks(&m, 1024 * 1024, None);
        assert_eq!(plans, vec![ChunkPlan::Zero; 3]);
    }

    #[test]
    fn an_unwritten_extent_plans_zero_like_a_hole() {
        let m = map(1024 * 1024, vec![zero(0, 1024 * 1024)]);
        assert_eq!(
            plan_file_chunks(&m, 1024 * 1024, None),
            vec![ChunkPlan::Zero]
        );
    }

    #[test]
    fn a_fully_shared_chunk_with_matching_base_reuses() {
        let child = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        let base = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, Some(&base)),
            vec![ChunkPlan::ReuseBase]
        );
    }

    #[test]
    fn shared_extents_with_different_physical_blocks_are_read() {
        // Shared with something else, not with the base: no byte proof.
        let child = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        let base = map(1024 * 1024, vec![data(0, 1024 * 1024, 8192, true)]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, Some(&base)),
            vec![ChunkPlan::Read]
        );
    }

    #[test]
    fn an_unshared_child_extent_is_read_even_when_base_matches() {
        let child = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, false)]);
        let base = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, Some(&base)),
            vec![ChunkPlan::Read]
        );
    }

    #[test]
    fn an_opaque_child_region_forces_read() {
        let child = map(1024 * 1024, vec![opaque(0, 1024 * 1024)]);
        let base = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, Some(&base)),
            vec![ChunkPlan::Read]
        );
    }

    #[test]
    fn a_partially_changed_chunk_is_read_in_full() {
        // First half of the chunk is shared with base; second half diverged.
        let child = map(
            1024 * 1024,
            vec![
                data(0, 512 * 1024, 4096, true),
                data(512 * 1024, 512 * 1024, 99999, false),
            ],
        );
        let base = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, Some(&base)),
            vec![ChunkPlan::Read]
        );
    }

    #[test]
    fn mixed_chunks_plan_independently() {
        // Chunk 0 shared with base, chunk 1 written (own blocks), chunk 2 a hole.
        let len = 3 * 1024 * 1024;
        let child = map(
            len,
            vec![
                data(0, 1024 * 1024, 4096, true),
                data(1024 * 1024, 1024 * 1024, 7777, false),
            ],
        );
        let base = map(len, vec![data(0, 2 * 1024 * 1024, 4096, true)]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, Some(&base)),
            vec![ChunkPlan::ReuseBase, ChunkPlan::Read, ChunkPlan::Zero]
        );
    }

    #[test]
    fn merged_base_extents_cover_a_child_segment_spanning_boundary() {
        // The child's segment boundaries need not equal the base's: physical
        // equality is checked per logical range, not per struct.
        let child = map(
            1024 * 1024,
            vec![
                data(0, 512 * 1024, 4096, true),
                data(512 * 1024, 512 * 1024, 4096 + 512 * 1024, true),
            ],
        );
        let base = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, Some(&base)),
            vec![ChunkPlan::ReuseBase]
        );
    }

    #[test]
    fn a_base_hole_where_the_child_has_data_is_read() {
        let child = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        let base = map(1024 * 1024, vec![]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, Some(&base)),
            vec![ChunkPlan::Read]
        );
    }

    #[test]
    fn without_a_base_everything_stored_is_read() {
        let child = map(1024 * 1024, vec![data(0, 1024 * 1024, 4096, true)]);
        assert_eq!(
            plan_file_chunks(&child, 1024 * 1024, None),
            vec![ChunkPlan::Read]
        );
    }

    #[test]
    fn a_final_partial_chunk_is_planned() {
        let m = map(1024 * 1024 + 1, vec![data(0, 1024 * 1024 + 1, 4096, false)]);
        assert_eq!(plan_file_chunks(&m, 1024 * 1024, None).len(), 2);
    }

    #[test]
    fn empty_and_zero_chunk_len_files_plan_nothing() {
        let m = map(0, vec![]);
        assert!(plan_file_chunks(&m, 1024 * 1024, None).is_empty());
        let m = map(10, vec![]);
        assert!(plan_file_chunks(&m, 0, None).is_empty());
    }

    // Live FIEMAP, Linux only: exercises the real ioctl and buffer layout,
    // which the synthetic-map tests above cannot. Skips silently on
    // filesystems without FIEMAP (the error path is the portable contract).
    #[cfg(target_os = "linux")]
    #[test]
    fn live_fiemap_reports_data_and_holes_for_a_real_sparse_file() {
        use std::io::{Seek, SeekFrom, Write};

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sparse.bin");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&vec![0x5a; 2 * 1024 * 1024]).unwrap();
        file.seek(SeekFrom::Start(6 * 1024 * 1024)).unwrap();
        file.write_all(&vec![0x5a; 1024 * 1024]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let Ok(map) = crate::extent::extent_map(&path) else {
            return;
        };
        assert_eq!(map.len, 7 * 1024 * 1024);
        let plans = plan_file_chunks(&map, 1024 * 1024, None);
        assert_eq!(plans.len(), 7);
        assert_eq!(
            plans.iter().filter(|p| **p == ChunkPlan::Zero).count(),
            4,
            "the 4 hole chunks plan Zero on any FIEMAP-capable fs: {plans:?}"
        );
        assert_eq!(
            plans.iter().filter(|p| **p == ChunkPlan::Read).count(),
            3,
            "unshared data chunks plan Read without a base: {plans:?}"
        );
    }

    // Live end-to-end reuse proof: on a reflink-capable Linux filesystem
    // (btrfs/xfs), a FICLONE clone shares physical extents with its source,
    // and the planner must turn that into ReuseBase chunks. Everywhere else
    // the clone is a byte copy and there is nothing to reuse — skip.
    #[cfg(target_os = "linux")]
    #[test]
    fn live_reflink_clone_chunks_plan_reuse_against_the_clone_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.bin");
        std::fs::write(&src, vec![0x7e; 4 * 1024 * 1024]).unwrap();
        let dst = tmp.path().join("dst.bin");
        if crate::clone::reflink_or_err(&src, &dst).is_err() {
            return;
        }
        let (Ok(child), Ok(base)) = (
            crate::extent::extent_map(&dst),
            crate::extent::extent_map(&src),
        ) else {
            return;
        };
        let plans = plan_file_chunks(&child, 1024 * 1024, Some(&base));
        assert!(
            plans.iter().all(|p| *p == ChunkPlan::ReuseBase),
            "a pristine reflink clone must plan full reuse: {plans:?}"
        );
    }
}
