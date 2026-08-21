//! Read-only filesystem audit — a small subset of `ext4 audit tool -n`.
//!
//! Walks the directory tree from inode 2 (root), counting how many
//! directory entries reference each inode. Compares the observed
//! reference count against the inode's stored `i_links_count` and
//! flags mismatches. Also reports directories whose `..` entry does
//! not point at the true parent.
//!
//! Three surfaces:
//! - [`audit`] — synchronous, collects every [`Anomaly`] into a
//!   `Vec` on the returned [`AuditReport`]. Read-only; used by Rust
//!   callers and tests.
//! - [`audit_with_callbacks`] — same read-only walk, but emits
//!   per-phase progress and per-finding events through
//!   caller-supplied closures. Used by the C ABI
//!   (`fs_ext4_fsck_run`) so the host UI can stream progress and
//!   findings live without buffering the full anomaly list for huge
//!   volumes.
//! - [`audit_with_repair`] — same walk + an optional repair pass.
//!   When `repair == true` the function mutates the on-disk image
//!   through the journal writer to fix the subset of anomalies it
//!   knows how to repair (currently: duplicate dirents pointing at
//!   one directory inode, and link-count drift). The C ABI is
//!   intentionally not wired through to this surface yet — the
//!   stable shape of `Anomaly` plus a versioned ABI bump is a
//!   separate task.

use crate::bgd;
use crate::dir::{self, DirBlockIter, DirEntryType};
use crate::error::{Error, Result};
use crate::extent;
use crate::features;
use crate::fs::{BlockBuffer, Filesystem};
use crate::inode::Inode;
use crate::superblock::Superblock;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One problem found by [`audit`]. Each variant carries the inode or
/// path needed to act on the finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    /// A directory entry references an inode whose `i_links_count` is
    /// *less than* the observed reference count. Stored value is too
    /// low — fsck would increase it to `observed`.
    LinkCountTooLow {
        ino: u32,
        stored: u16,
        observed: u32,
    },
    /// Inode's `i_links_count` is *greater than* the observed reference
    /// count. Stored value is too high — fsck would decrease it.
    LinkCountTooHigh {
        ino: u32,
        stored: u16,
        observed: u32,
    },
    /// Dangling directory entry: a dir entry points to an inode with
    /// `i_links_count == 0` or one we couldn't read.
    ///
    /// `observed` is how many dirents reference `child_ino` from the
    /// audit's directory walk. For the readable-but-zero-links case
    /// the rescue path writes `observed` into the inode's
    /// `i_links_count` (it's the same fix as `LinkCountTooLow` from
    /// `stored=0`). For the unreadable case we synthesise
    /// `observed = 0` so the rescue is correctly refused — there's no
    /// safe way to repair an inode we can't read without orphan-list
    /// or `/lost+found` machinery.
    DanglingEntry {
        parent_ino: u32,
        child_ino: u32,
        observed: u32,
    },
    /// A directory's `..` entry does not point at its true parent.
    WrongDotDot {
        dir_ino: u32,
        claims: u32,
        actual_parent: u32,
    },
    /// A directory entry inside `parent_ino` claims its target
    /// (`child_ino`) is a directory, but the target inode's mode bits
    /// are not `S_IFDIR`. Read failures on the child are surfaced as
    /// `DanglingEntry` from the inodes phase instead. Carrying both
    /// inodes lets a repair pass either rewrite the dirent's
    /// `file_type` byte (when the child is a valid non-dir) or
    /// unlink the dirent.
    /// Carries the dirent's `name` so the repair pass can target the
    /// exact record by (parent, name) — necessary when the parent has
    /// multiple hardlinks to the same inode and only one of them has
    /// the wrong `file_type` byte. Stored as raw bytes since ext4
    /// dirent names are not required to be UTF-8.
    BogusEntry {
        parent_ino: u32,
        child_ino: u32,
        name: Vec<u8>,
    },
    /// One block group's free-block / free-inode counters drift from
    /// the bitmap reality. Either the bitmap claims fewer free bits
    /// than the descriptor says (over-count) or more (under-count).
    /// Common after crashes that interrupted bitmap+descriptor pairs
    /// mid-write. Repair walks the bitmap, recomputes the truth, and
    /// patches the descriptor (incl. checksum when metadata_csum is on).
    BlockGroupFreeCountDrift {
        group_index: u32,
        stored_blocks: u32,
        observed_blocks: u32,
        stored_inodes: u32,
        observed_inodes: u32,
    },
    /// Superblock free-block / free-inode totals don't match the sum
    /// across all group descriptors' (post-bitmap) counts. Independent
    /// of `BlockGroupFreeCountDrift`: the per-group descriptors might
    /// agree with their bitmaps but the SB total still disagree (e.g.
    /// a torn write of just the SB block). Repair recomputes from the
    /// bitmaps and writes the SB.
    SuperblockFreeCountDrift {
        stored_blocks: u64,
        observed_blocks: u64,
        stored_inodes: u32,
        observed_inodes: u32,
    },
    /// Multiple directory entries reference the same directory inode.
    /// Illegal — directories can have only one parent dirent (plus . and ..).
    /// Caused by an inode-allocator bug in early `apply_mkdir` (fixed) but
    /// the on-disk wreckage remains until repair runs.
    DuplicateDirentForDirInode {
        ino: u32,
        /// Every (parent_ino, name) tuple that references `ino`.
        /// Sorted: (parent_ino asc, name asc) — repair keeps element 0,
        /// removes the rest.
        dirents: Vec<(u32, String)>,
    },
}

/// Summary returned by [`audit`]. Empty `anomalies` means the subset
/// of invariants checked all held.
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    /// Every problem found, in no particular order. Populated by the
    /// legacy [`audit`] entry point; left empty by
    /// [`audit_with_callbacks`] (it streams findings through the
    /// caller's closure to avoid buffering on huge volumes).
    pub anomalies: Vec<Anomaly>,
    /// Number of distinct inodes visited via directory entries.
    pub inodes_visited: u32,
    /// Number of directory entries scanned (including `.`, `..`, and tombstones).
    pub entries_scanned: u64,
    /// Number of directories scanned.
    pub directories_scanned: u32,
    /// **Authoritative current count** of anomalies on the
    /// filesystem. After [`audit`] / [`audit_with_callbacks`] this
    /// is the count from the single scan. After a repair pass
    /// (`audit_with_repair` with `repair = true`) this is the
    /// **post-repair re-scan** count — the actual remaining
    /// problems on disk, NOT the pre-repair number minus repaired
    /// (which would be unreliable if our repair logic itself
    /// introduces new anomalies).
    pub anomalies_count: u64,
    /// Number of anomalies the audit ORIGINALLY found, before any
    /// repair commits. Equal to `anomalies_count` for non-repair
    /// runs. After a repair pass: `initial_anomalies_count -
    /// repaired_count` is what we *expect* to remain; the actual
    /// `anomalies_count` from the post-repair re-scan is what
    /// REALLY remains. Discrepancies between the two are how we
    /// notice repair logic has bugs.
    pub initial_anomalies_count: u64,
    /// Anomalies the repair pass actually mutated the disk to fix.
    /// Always zero unless [`audit_with_repair`] ran with `repair = true`.
    /// A repair that failed midway leaves this counter at the number of
    /// successfully-committed fixes — partial progress is intentional
    /// (each commit is its own journal transaction so a crash mid-pass
    /// can't compound the damage).
    pub repaired_count: u64,
}

impl AuditReport {
    pub fn is_clean(&self) -> bool {
        self.anomalies_count == 0
    }
}

/// Phase identifier for [`audit_with_callbacks`] progress callbacks.
///
/// Numeric values match `fs_ext4_fsck_phase_t` in `include/fs_ext4.h`
/// and **must not be reordered** — the C ABI is locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FsckPhase {
    Superblock = 0,
    Journal = 1,
    Directory = 2,
    Inodes = 3,
    Finalize = 4,
}

impl FsckPhase {
    /// Short ASCII label, mirrored to the C ABI.
    pub fn name(self) -> &'static str {
        match self {
            FsckPhase::Superblock => "superblock",
            FsckPhase::Journal => "journal",
            FsckPhase::Directory => "directory",
            FsckPhase::Inodes => "inodes",
            FsckPhase::Finalize => "finalize",
        }
    }
}

/// Walk the filesystem from `/`, counting directory-entry references
/// to each inode and comparing against each inode's `i_links_count`.
///
/// Capped by `max_dirs_visited` and `max_entries_per_dir` so a
/// deliberately-cyclic or extremely large image can still be audited
/// in bounded time. For a real fsck pass, set both to `u32::MAX`.
pub fn audit(
    fs: &Filesystem,
    max_dirs_visited: u32,
    max_entries_per_dir: u32,
) -> Result<AuditReport> {
    let mut report = AuditReport::default();
    let mut collected: Vec<Anomaly> = Vec::new();
    audit_inner(
        fs,
        max_dirs_visited,
        max_entries_per_dir,
        &mut |_, _, _| {},
        &mut |a| collected.push(a.clone()),
        &mut report,
    )?;
    report.anomalies = collected;
    Ok(report)
}

/// Same walk as [`audit`], but emits progress and findings through
/// caller-supplied closures. The callbacks see each [`Anomaly`] as it
/// is discovered (no buffering of the full list) and per-phase
/// progress so a host UI can render a live progress bar.
///
/// On return, `report.anomalies` is **empty** — findings are delivered
/// only through `on_finding`. The summary counters
/// (`directories_scanned`, `entries_scanned`, `inodes_visited`,
/// `anomalies_found` … via the C ABI helpers) are still populated.
///
/// Phase emission contract:
/// - `Superblock` once at start (0/1 → 1/1) — superblock validity
///   was already checked at mount.
/// - `Directory` per directory popped (`done` = directories scanned
///   so far, `total` = scanned + queue depth).
/// - `Inodes` once around the link-count comparison pass (0/1 → 1/1).
/// - `Finalize` once just before return (0/1 → 1/1).
///
/// `Journal` is **not** emitted here — the FFI shim drives journal
/// replay before calling this function and emits the phase from
/// there.
pub fn audit_with_callbacks<P, F>(
    fs: &Filesystem,
    max_dirs_visited: u32,
    max_entries_per_dir: u32,
    mut on_progress: P,
    mut on_finding: F,
) -> Result<AuditReport>
where
    P: FnMut(FsckPhase, u64, u64),
    F: FnMut(&Anomaly),
{
    let mut report = AuditReport::default();
    on_progress(FsckPhase::Superblock, 0, 1);
    on_progress(FsckPhase::Superblock, 1, 1);

    audit_inner(
        fs,
        max_dirs_visited,
        max_entries_per_dir,
        &mut on_progress,
        &mut on_finding,
        &mut report,
    )?;

    Ok(report)
}

/// Core walk shared by [`audit`] and [`audit_with_callbacks`].
///
/// Findings are emitted through `on_finding`; nothing is pushed onto
/// `report.anomalies` from here. Callers that want the legacy
/// "collect into a vec" behaviour wrap `on_finding` accordingly.
fn audit_inner(
    fs: &Filesystem,
    max_dirs_visited: u32,
    max_entries_per_dir: u32,
    on_progress: &mut dyn FnMut(FsckPhase, u64, u64),
    on_finding: &mut dyn FnMut(&Anomaly),
    report: &mut AuditReport,
) -> Result<()> {
    // Observed: ino → reference-count.
    let mut observed: HashMap<u32, u32> = HashMap::new();
    // What each directory's ".." entry CLAIMS the parent is (read off
    // disk). Compared post-walk against `actual_parent` to flag
    // WrongDotDot.
    let mut parent_claim: HashMap<u32, u32> = HashMap::new();
    // The directory that ACTUALLY enqueued each child during the walk
    // — this is the source of truth for "who is your parent?". Built
    // up as we pop work items. Root maps to itself by convention so a
    // corrupted root ".." still flags WrongDotDot.
    let mut actual_parent: HashMap<u32, u32> = HashMap::new();
    // Directories we couldn't fully walk (parse failure, inline overflow
    // we don't decode, bound cap). Any link-count anomalies that could
    // have been explained by their missing entries are suppressed below.
    let mut incomplete_dirs: std::collections::HashSet<u32> = std::collections::HashSet::new();
    // ino → list of (parent_ino, name_bytes) that reference it. Skips
    // "." / ".." (those are self-references, not aliases). Kept as
    // bytes so non-UTF-8 names (legal on ext4) round-trip; the
    // `DuplicateDirentForDirInode` variant lossy-converts to String at
    // emission time only, since the user-visible report can tolerate
    // U+FFFD where the disk has a non-UTF-8 byte.
    let mut dirent_index: HashMap<u32, Vec<(u32, Vec<u8>)>> = HashMap::new();

    // (ino, parent_ino, dirent_name) — `dirent_name` is the name in
    // `parent_ino` whose dirent points at `ino`. Carried so a
    // `BogusEntry` finding can disambiguate when the parent has
    // multiple hardlinks to the same inode. Empty for the root
    // self-seed (root never triggers BogusEntry — its inode is
    // always a directory).
    let mut work: Vec<(u32, u32, Vec<u8>)> = Vec::new();
    work.push((
        crate::path::EXT4_ROOT_INODE,
        crate::path::EXT4_ROOT_INODE,
        Vec::new(),
    ));
    let mut visited: std::collections::HashSet<u32> = std::collections::HashSet::new();

    let has_filetype = fs.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
    let block_size = fs.sb.block_size();

    // Initial directory progress pulse: 0 of (just root).
    on_progress(FsckPhase::Directory, 0, work.len() as u64);

    while let Some((dir_ino, parent_ino, dirent_name)) = work.pop() {
        if report.directories_scanned >= max_dirs_visited {
            incomplete_dirs.insert(dir_ino);
            break;
        }
        if !visited.insert(dir_ino) {
            continue;
        }
        // Record who really enqueued us. `parent_ino` is the directory
        // we were popped under; for the root self-seed it's root
        // itself. First-seen wins on the rare case a buggy filesystem
        // has the same inode reachable from two different parents
        // (the duplicate-dirent class is detected separately).
        actual_parent.entry(dir_ino).or_insert(parent_ino);
        report.directories_scanned += 1;

        let (inode, _raw) = match fs.read_inode_verified(dir_ino) {
            Ok(p) => p,
            Err(_) => {
                incomplete_dirs.insert(dir_ino);
                emit_dir_progress(on_progress, report.directories_scanned, work.len());
                continue;
            }
        };
        if !inode.is_dir() {
            // Parent claimed this child was a directory (file_type
            // byte in the dirent) but the inode's mode bits disagree.
            // Carry both inodes plus the dirent name so a repair pass
            // can either rewrite the dirent's file_type byte (precise
            // (parent, name) match avoids hardlink ambiguity) or
            // unlink the dirent.
            let a = Anomaly::BogusEntry {
                parent_ino,
                child_ino: dir_ino,
                name: dirent_name.clone(),
            };
            on_finding(&a);
            report.anomalies_count += 1;
            emit_dir_progress(on_progress, report.directories_scanned, work.len());
            continue;
        }

        // Skip directories the audit can't fully enumerate (inline dirs
        // whose entries overflow into the xattr region — a valid
        // on-disk layout we don't decode here).
        if inode.has_inline_data() {
            incomplete_dirs.insert(dir_ino);
            emit_dir_progress(on_progress, report.directories_scanned, work.len());
            continue;
        }

        let entries = match collect_dir_entries(fs, &inode, has_filetype, block_size) {
            Ok(e) => e,
            Err(_) => {
                incomplete_dirs.insert(dir_ino);
                emit_dir_progress(on_progress, report.directories_scanned, work.len());
                continue;
            }
        };

        let mut truncated = false;
        for (n_scanned, entry) in (0u32..).zip(entries) {
            if n_scanned >= max_entries_per_dir {
                truncated = true;
                break;
            }
            report.entries_scanned += 1;

            if entry.name == b"." {
                *observed.entry(dir_ino).or_insert(0) += 1;
                continue;
            }
            if entry.name == b".." {
                parent_claim.insert(dir_ino, entry.inode);
                *observed.entry(entry.inode).or_insert(0) += 1;
                continue;
            }

            *observed.entry(entry.inode).or_insert(0) += 1;
            // Track every real (parent, name) edge so the post-walk
            // pass can flag inodes referenced by more than one dirent.
            dirent_index
                .entry(entry.inode)
                .or_default()
                .push((dir_ino, entry.name.clone()));

            if matches!(entry.file_type, DirEntryType::Directory) {
                work.push((entry.inode, dir_ino, entry.name.clone()));
            }
        }
        if truncated {
            incomplete_dirs.insert(dir_ino);
        }
        emit_dir_progress(on_progress, report.directories_scanned, work.len());
    }

    report.inodes_visited = observed.len() as u32;

    // Inode link-count compare phase.
    let inodes_total = observed.len() as u64;
    on_progress(FsckPhase::Inodes, 0, inodes_total.max(1));

    // Compare observed vs stored. When an inode's reference came from a
    // directory we couldn't fully enumerate, we suppress TooHigh (we
    // under-counted) but still report TooLow (we already saw more than
    // the stored value — the image is genuinely wrong).
    let have_incomplete = !incomplete_dirs.is_empty();
    let mut inodes_done: u64 = 0;
    let mut last_tick = Instant::now();
    let tick = Duration::from_millis(500);
    for (&ino, &count) in observed.iter() {
        match fs.read_inode_verified(ino) {
            Ok((inode, _)) => {
                let stored = inode.links_count;
                if stored == 0 {
                    let a = Anomaly::DanglingEntry {
                        parent_ino: 0,
                        child_ino: ino,
                        observed: count,
                    };
                    on_finding(&a);
                    report.anomalies_count += 1;
                    continue;
                }
                if (stored as u32) < count {
                    let a = Anomaly::LinkCountTooLow {
                        ino,
                        stored,
                        observed: count,
                    };
                    on_finding(&a);
                    report.anomalies_count += 1;
                }
                if (stored as u32) > count && !have_incomplete {
                    let a = Anomaly::LinkCountTooHigh {
                        ino,
                        stored,
                        observed: count,
                    };
                    on_finding(&a);
                    report.anomalies_count += 1;
                }
            }
            Err(_) => {
                // Unreadable inode that somebody linked to. Surface
                // observed = 0 as a sentinel meaning "rescue not safe"
                // — repair_link_count refuses observed == 0 already,
                // so the rescue path correctly leaves this case alone.
                let a = Anomaly::DanglingEntry {
                    parent_ino: 0,
                    child_ino: ino,
                    observed: 0,
                };
                on_finding(&a);
                report.anomalies_count += 1;
            }
        }
        inodes_done += 1;
        if last_tick.elapsed() >= tick {
            on_progress(FsckPhase::Inodes, inodes_done, inodes_total.max(1));
            last_tick = Instant::now();
        }
    }

    // Surface inodes referenced by more than one dirent that are
    // themselves directories. Multi-link is fine for files (POSIX
    // hardlinks) but illegal for dirs; the canonical case here is the
    // pre-fix `apply_mkdir` allocator bug which left N siblings all
    // pointing at the same inode. Detection runs over the index built
    // during the walk; emission order is sorted so repair has a
    // deterministic "keep first" choice.
    let mut dup_keys: Vec<u32> = dirent_index
        .iter()
        .filter_map(|(ino, refs)| if refs.len() > 1 { Some(*ino) } else { None })
        .collect();
    dup_keys.sort_unstable();
    for ino in dup_keys {
        // Only directories trip the alias rule. Files with multiple
        // dirents are normal hardlinks and already covered by the
        // link-count comparison above.
        let is_dir = match fs.read_inode_verified(ino) {
            Ok((inode, _)) => inode.is_dir(),
            // Unreadable inodes were already reported as DanglingEntry;
            // skip here rather than double-count.
            Err(_) => continue,
        };
        if !is_dir {
            continue;
        }
        let mut refs = dirent_index.get(&ino).cloned().unwrap_or_default();
        refs.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let dirents: Vec<(u32, String)> = refs
            .into_iter()
            .map(|(p, n)| (p, String::from_utf8_lossy(&n).into_owned()))
            .collect();
        let a = Anomaly::DuplicateDirentForDirInode { ino, dirents };
        on_finding(&a);
        report.anomalies_count += 1;
    }

    // Check `..` claims against the actual enqueueing parent. Root
    // is special-cased to compare against itself (ext4 convention:
    // root's ".." points at root). For every other directory we
    // compare against `actual_parent` — the directory that enqueued
    // it during the walk. A directory we never reached has no
    // entry in `actual_parent`; we skip those (any anomaly inside an
    // unreachable subtree is invisible to the audit by definition).
    for (&dir_ino, &claimed) in parent_claim.iter() {
        let truth = if dir_ino == crate::path::EXT4_ROOT_INODE {
            crate::path::EXT4_ROOT_INODE
        } else {
            match actual_parent.get(&dir_ino) {
                Some(&p) => p,
                None => continue,
            }
        };
        if claimed != truth {
            let a = Anomaly::WrongDotDot {
                dir_ino,
                claims: claimed,
                actual_parent: truth,
            };
            on_finding(&a);
            report.anomalies_count += 1;
        }
    }

    on_progress(FsckPhase::Inodes, inodes_total.max(1), inodes_total.max(1));

    // Free-count drift scan. Walks every group's block + inode bitmaps,
    // counts the free bits, compares against the descriptors and the
    // superblock. Emits per-group + per-superblock drift findings as
    // it goes. Folded under the existing Inodes phase rather than its
    // own phase so the C ABI's locked phase enum doesn't need
    // extending.
    audit_free_counts(fs, on_finding, report)?;

    on_progress(FsckPhase::Finalize, 0, 1);
    on_progress(FsckPhase::Finalize, 1, 1);

    Ok(())
}

/// Walk every block group's bitmaps, count free bits, and emit
/// drift findings against the on-disk descriptors and superblock.
/// Detection only — repair is wired through `audit_with_repair`.
///
/// The bits past a group's actual block/inode range are reserved as
/// "always allocated" (set to 1) on a healthy ext4 image; we only
/// count zero bits within `[0, group_size_bits)` to mirror that
/// convention so a partial last group doesn't get double-counted.
fn audit_free_counts(
    fs: &Filesystem,
    on_finding: &mut dyn FnMut(&Anomaly),
    report: &mut AuditReport,
) -> Result<()> {
    let bpg = fs.sb.blocks_per_group as u64;
    let ipg = fs.sb.inodes_per_group as u64;
    let total_blocks = fs.sb.blocks_count;
    let first_data = fs.sb.first_data_block as u64;

    // Re-read BGDs and SB from disk for each scan rather than
    // trusting `fs.groups` / `fs.sb` (mount-time snapshots, never
    // mutated). The post-repair re-scan needs the patched values to
    // avoid re-emitting drift findings the repair pass just fixed:
    // bitmaps come from `fs.read_block` (sees pinned post-commit
    // bytes), so the comparison's "stored" side has to match — read
    // the descriptors and SB the same way for both halves of the
    // compare to look at the same point in time.
    let live_groups = bgd::read_all(fs.dev.as_ref(), &fs.sb, &fs.csum)?;
    let live_sb = Superblock::read(fs.dev.as_ref())?;

    let mut sum_free_blocks: u64 = 0;
    let mut sum_free_inodes: u64 = 0;

    for (gi, bg) in live_groups.iter().enumerate() {
        // Block bitmap: count zero bits across the bytes covering the
        // bits that actually correspond to this group's blocks. The
        // last group may be partial. Go through `read_block` so the
        // post-repair re-scan sees post-commit-pre-checkpoint pinned
        // bytes — `dev.read_at` would skip the cache and surface the
        // stale on-disk image, falsely re-emitting drift findings the
        // repair pass just fixed.
        let group_first_block = first_data + gi as u64 * bpg;
        let group_block_count = std::cmp::min(bpg, total_blocks.saturating_sub(group_first_block));
        let block_bitmap = fs.read_block(bg.block_bitmap)?;
        let observed_blocks = count_zero_bits_le(&block_bitmap, group_block_count as u32);

        // Inode bitmap: every group has exactly inodes_per_group
        // inodes (the ext4 layout doesn't leave a partial last group
        // for inodes; the trailing bits are reserved-as-1).
        let inode_bitmap = fs.read_block(bg.inode_bitmap)?;
        let observed_inodes = count_zero_bits_le(&inode_bitmap, ipg as u32);

        sum_free_blocks += observed_blocks as u64;
        sum_free_inodes += observed_inodes as u64;

        if observed_blocks != bg.free_blocks_count || observed_inodes != bg.free_inodes_count {
            let a = Anomaly::BlockGroupFreeCountDrift {
                group_index: gi as u32,
                stored_blocks: bg.free_blocks_count,
                observed_blocks,
                stored_inodes: bg.free_inodes_count,
                observed_inodes,
            };
            on_finding(&a);
            report.anomalies_count += 1;
        }
    }

    // SB totals. Compare against the BITMAP-derived sum, not the
    // descriptor-derived sum — a torn SB write can leave the SB
    // disagreeing with descriptors that themselves agree with the
    // bitmaps. We want the truth.
    if sum_free_blocks != live_sb.free_blocks_count
        || (sum_free_inodes as u32) != live_sb.free_inodes_count
    {
        let a = Anomaly::SuperblockFreeCountDrift {
            stored_blocks: live_sb.free_blocks_count,
            observed_blocks: sum_free_blocks,
            stored_inodes: live_sb.free_inodes_count,
            observed_inodes: sum_free_inodes as u32,
        };
        on_finding(&a);
        report.anomalies_count += 1;
    }
    Ok(())
}

/// Count zero (= free) bits inside the first `total_bits` bits of a
/// little-endian bitmap. Bits beyond `total_bits` are treated as
/// "reserved/allocated" and are NOT counted, even when the bitmap
/// happens to have them at zero — matches the ext4 convention for
/// trailing reserved bits in a partial group.
fn count_zero_bits_le(buf: &[u8], total_bits: u32) -> u32 {
    let full_bytes = (total_bits / 8) as usize;
    let mut free: u32 = 0;
    for i in 0..full_bytes {
        if i >= buf.len() {
            break;
        }
        free += buf[i].count_zeros();
    }
    let leftover_bits = total_bits % 8;
    if leftover_bits > 0 && full_bytes < buf.len() {
        let last = buf[full_bytes];
        let mask = (1u8 << leftover_bits) - 1;
        let ones_in_used_bits = (last & mask).count_ones();
        free += leftover_bits - ones_in_used_bits;
    }
    free
}

fn emit_dir_progress(
    on_progress: &mut dyn FnMut(FsckPhase, u64, u64),
    scanned: u32,
    queue_len: usize,
) {
    let done = scanned as u64;
    let total = done + queue_len as u64;
    on_progress(FsckPhase::Directory, done, total);
}

fn collect_dir_entries(
    fs: &Filesystem,
    inode: &Inode,
    has_filetype: bool,
    block_size: u32,
) -> Result<Vec<crate::dir::DirEntry>> {
    let mut entries = Vec::new();
    if inode.has_inline_data() {
        for entry in DirBlockIter::new(&inode.block, has_filetype) {
            entries.push(entry?);
        }
        return Ok(entries);
    }
    if !inode.has_extents() {
        return Err(Error::Corrupt(
            "legacy non-extent dirs not supported by audit",
        ));
    }
    let total_blocks = inode.size.div_ceil(block_size as u64);
    let mut buf = vec![0u8; block_size as usize];
    for logical in 0..total_blocks {
        let Some(phys) = extent::map_logical(&inode.block, fs.dev.as_ref(), block_size, logical)?
        else {
            continue;
        };
        let offset = phys
            .checked_mul(block_size as u64)
            .ok_or(Error::Corrupt("audit: dir block offset overflow"))?;
        fs.dev.read_at(offset, &mut buf)?;
        for entry in DirBlockIter::new(&buf, has_filetype) {
            // Ignore parse errors on dx_root first block of indexed dirs
            match entry {
                Ok(e) => entries.push(e),
                Err(_) if logical == 0 => continue,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(entries)
}

/// Audit, then optionally repair the subset of anomalies the repair
/// pass knows how to fix. When `repair == false` this is the read+write
/// equivalent of [`audit_with_callbacks`] — same findings, no disk
/// mutation. When `repair == true`, after the read pass completes the
/// function walks `report.anomalies` and commits a fix per repairable
/// finding through the journal writer.
///
/// Repairable today:
/// - [`Anomaly::DuplicateDirentForDirInode`]: keeps `dirents[0]`, removes
///   the rest from their respective parent directories, then recomputes
///   the surviving directory's `i_links_count` from a fresh count of its
///   subdirectories.
/// - [`Anomaly::LinkCountTooLow`] / [`Anomaly::LinkCountTooHigh`]: writes
///   the observed count back into `i_links_count`.
///
/// Each repair commit is its own [`BlockBuffer`] transaction. Crash
/// mid-pass: the surviving on-disk state is the union of fixes that
/// committed up to that point; subsequent fsck runs continue from
/// there. `report.repaired_count` reflects how many fixes actually
/// landed (0 if `repair == false`).
///
/// The `findings` collected via `on_finding` and the `report.anomalies`
/// vec follow the same population contract as [`audit`] /
/// [`audit_with_callbacks`]: whichever caller wires up the closure
/// gets the streaming events; the returned report counts are always
/// authoritative.
pub fn audit_with_repair<P, F>(
    fs: &Filesystem,
    max_dirs_visited: u32,
    max_entries_per_dir: u32,
    mut on_progress: P,
    mut on_finding: F,
    repair: bool,
) -> Result<AuditReport>
where
    P: FnMut(FsckPhase, u64, u64),
    F: FnMut(&Anomaly),
{
    // Refuse repair on read-only mounts before any scanning. The full
    // walk is expensive, and a refused repair shouldn't look like a
    // partially-successful audit to the caller.
    if repair && !fs.dev.is_writable() {
        return Err(Error::ReadOnly);
    }

    let mut report = AuditReport::default();
    on_progress(FsckPhase::Superblock, 0, 1);
    on_progress(FsckPhase::Superblock, 1, 1);

    // Buffer findings locally so the repair pass can iterate them
    // without re-walking. The caller's closure still sees each finding
    // streamed as it's discovered — we tee through `on_finding`.
    let mut collected: Vec<Anomaly> = Vec::new();
    audit_inner(
        fs,
        max_dirs_visited,
        max_entries_per_dir,
        &mut on_progress,
        &mut |a| {
            on_finding(a);
            collected.push(a.clone());
        },
        &mut report,
    )?;

    // Snapshot the pre-repair count before anything mutates state.
    // Even non-repair runs get this for symmetry — both fields will
    // hold the same number on a `repair = false` call.
    report.initial_anomalies_count = report.anomalies_count;

    if !repair {
        report.anomalies = collected;
        return Ok(report);
    }

    // For directories that ALSO appear in a DuplicateDirentForDirInode
    // finding, the captured `actual_parent` is the parent the walker
    // saw first — which may not be the one that survives dedup
    // (`repair_duplicate_dir_inode` keeps `dirents[0]`). Override the
    // WrongDotDot target with the post-dedup surviving parent so we
    // don't rewrite `..` to point at the alias we just removed.
    let surviving_parent_after_dedup: HashMap<u32, u32> = collected
        .iter()
        .filter_map(|a| match a {
            Anomaly::DuplicateDirentForDirInode { ino, dirents } if !dirents.is_empty() => {
                Some((*ino, dirents[0].0))
            }
            _ => None,
        })
        .collect();

    for finding in &collected {
        match finding {
            Anomaly::DuplicateDirentForDirInode { ino, dirents } => {
                repair_duplicate_dir_inode(fs, *ino, dirents, &mut report)?;
            }
            Anomaly::LinkCountTooLow {
                ino,
                stored: _,
                observed,
            }
            | Anomaly::LinkCountTooHigh {
                ino,
                stored: _,
                observed,
            } => {
                repair_link_count(fs, *ino, *observed, &mut report)?;
            }
            Anomaly::WrongDotDot {
                dir_ino,
                claims: _,
                actual_parent,
            } => {
                let target_parent = surviving_parent_after_dedup
                    .get(dir_ino)
                    .copied()
                    .unwrap_or(*actual_parent);
                repair_wrong_dotdot(fs, *dir_ino, target_parent, &mut report)?;
            }
            Anomaly::BogusEntry {
                parent_ino,
                child_ino,
                name,
            } => {
                repair_bogus_entry(fs, *parent_ino, *child_ino, name, &mut report)?;
            }
            Anomaly::DanglingEntry {
                parent_ino: _,
                child_ino,
                observed,
            } => {
                // Rescue: write observed into the inode's links_count
                // when the inode is readable. The unreadable case
                // arrives with observed = 0 and repair_link_count
                // refuses that, leaving the anomaly for a future
                // orphan-list / lost+found path.
                repair_link_count(fs, *child_ino, *observed, &mut report)?;
            }
            Anomaly::BlockGroupFreeCountDrift {
                group_index,
                stored_blocks,
                observed_blocks,
                stored_inodes,
                observed_inodes,
            } => {
                repair_block_group_free_counts(
                    fs,
                    *group_index,
                    *stored_blocks,
                    *observed_blocks,
                    *stored_inodes,
                    *observed_inodes,
                    &mut report,
                )?;
            }
            Anomaly::SuperblockFreeCountDrift {
                stored_blocks,
                observed_blocks,
                stored_inodes,
                observed_inodes,
            } => {
                repair_superblock_free_counts(
                    fs,
                    *stored_blocks,
                    *observed_blocks,
                    *stored_inodes,
                    *observed_inodes,
                    &mut report,
                )?;
            }
        }
    }

    // Post-repair re-scan. Walking the tree again is expensive, but
    // it's the only way to give the caller a TRUTHFUL "what's still
    // wrong" count. If our repair logic accidentally introduced new
    // anomalies (or didn't actually fix the ones we thought we fixed),
    // this re-scan surfaces it as a count mismatch:
    //   expected_remaining = initial_anomalies_count - repaired_count
    //   actual_remaining   = anomalies_count (from this re-scan)
    // The caller's `on_progress` is reused so the host UI keeps
    // rendering progress for the second walk. `on_finding` is a
    // no-op closure here because the pre-repair stream already gave
    // the caller the per-finding detail and re-emitting would
    // double-count in the UI — but we DO buffer remaining findings
    // locally so `report.anomalies` reflects the post-repair truth
    // (consistent with `report.anomalies_count`).
    let mut post_report = AuditReport::default();
    let mut remaining: Vec<Anomaly> = Vec::new();
    audit_inner(
        fs,
        max_dirs_visited,
        max_entries_per_dir,
        &mut on_progress,
        &mut |a| {
            remaining.push(a.clone());
        },
        &mut post_report,
    )?;

    // Replace the live count + anomalies list with the post-repair
    // numbers. Keep `initial_anomalies_count` unchanged so the
    // caller can see the before-vs-after delta.
    report.anomalies = remaining;
    report.anomalies_count = post_report.anomalies_count;

    Ok(report)
}

/// Repair a `DuplicateDirentForDirInode` finding.
///
/// `dirents` is sorted (parent_ino asc, name asc). We keep
/// `dirents[0]` as the canonical edge and remove every entry in
/// `dirents[1..]` from its parent block. Each removal is a separate
/// journal commit so a crash mid-loop leaves a deterministic
/// partial-fix state (some duplicates gone, the rest still pending —
/// fsck on next mount finishes the job).
///
/// After the duplicates are gone we recompute the kept directory's
/// `i_links_count` from a fresh subdir count: ext4 link count for a
/// dir is `2 + (number of child subdirectories)` (2 = self via "." +
/// parent's dirent). Stale link counts caused by the multi-parent
/// state are corrected here so a subsequent audit returns clean.
fn repair_duplicate_dir_inode(
    fs: &Filesystem,
    ino: u32,
    dirents: &[(u32, String)],
    report: &mut AuditReport,
) -> Result<()> {
    if dirents.len() < 2 {
        // Defensive — detection only emits this variant when len > 1.
        return Ok(());
    }

    let has_ft = fs.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
    let bs = fs.sb.block_size();

    // Drop every duplicate edge except the first. Each iteration reads
    // the parent's dir blocks fresh so a previous removal in the same
    // parent (rare — needs two duplicates with the same parent) is
    // visible. `repaired_count` advances once per finding, not once
    // per alias removed — the caller's
    // `initial_anomalies_count - repaired_count` reconciliation
    // counts findings, so a 3-alias finding still represents one
    // repaired anomaly.
    let mut any_removed = false;
    for (parent_ino, name) in dirents.iter().skip(1) {
        let (parent_inode, _parent_raw) = fs.read_inode_verified(*parent_ino)?;
        if !parent_inode.is_dir() {
            // The parent itself isn't a directory anymore — bail on
            // this duplicate and let a later pass clean up.
            continue;
        }
        let mut buf = BlockBuffer::new(bs);
        let parent_blocks = parent_inode.size.div_ceil(bs as u64);
        let mut removed = false;
        for logical in 0..parent_blocks {
            let Some(phys) = fs.map_inode_logical(&parent_inode, logical)? else {
                continue;
            };
            let block = buf.get_mut(fs, phys)?;
            // dir_entry_tail occupies the last 12 bytes when
            // metadata_csum is on. Mirror apply_unlink's reservation
            // so removal doesn't scribble the tail.
            let reserved_tail = if fs.csum.enabled && dir::has_csum_tail(block) {
                12
            } else {
                0
            };
            if dir::remove_entry_from_block(block, name.as_bytes(), has_ft, reserved_tail)? {
                if fs.csum.enabled && reserved_tail == 12 {
                    let end = block.len();
                    let mut c =
                        crate::checksum::linux_crc32c(fs.csum.seed, &parent_ino.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
                    c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
                    block[end - 4..end].copy_from_slice(&c.to_le_bytes());
                }
                removed = true;
                break;
            }
        }
        if !removed {
            // Detection saw the dirent but the on-disk parent doesn't
            // contain it now — racy concurrent mutation, or audit was
            // run with a partial cache. Skip rather than fail the
            // whole pass; the next audit will resurface or clear it.
            continue;
        }
        fs.commit_block_buffer(buf)?;
        any_removed = true;
    }
    if any_removed {
        report.repaired_count += 1;
    }

    // Recompute i_links_count for the surviving directory. Walking
    // children counts only proper subdirectories (not "." / "..") —
    // the canonical formula for a directory's nlink in ext4.
    let (kept_inode, mut kept_raw) = fs.read_inode_verified(ino)?;
    if !kept_inode.is_dir() {
        return Ok(());
    }
    let subdir_count = count_subdirs(fs, &kept_inode, has_ft, bs)?;
    let new_nlink: u16 = 2u16.saturating_add(subdir_count.min(u16::MAX as u32 - 2) as u16);
    kept_raw[0x1A..0x1C].copy_from_slice(&new_nlink.to_le_bytes());
    finalize_and_commit_inode(fs, ino, kept_inode.generation, &mut kept_raw)?;
    Ok(())
}

/// Walk `dir_inode`'s data blocks and count entries whose file_type is
/// Directory, excluding "." and "..". Used by repair to recompute
/// `i_links_count` from scratch after removing duplicate dirents.
fn count_subdirs(
    fs: &Filesystem,
    dir_inode: &Inode,
    has_filetype: bool,
    block_size: u32,
) -> Result<u32> {
    let entries = collect_dir_entries(fs, dir_inode, has_filetype, block_size)?;
    let mut n = 0u32;
    for e in entries {
        if e.name == b"." || e.name == b".." {
            continue;
        }
        // Don't trust the dirent's `file_type` byte — that's exactly
        // what `BogusEntry` exists to detect. Verify the child
        // inode's mode bits before counting. Unreadable children and
        // mode mismatches are silently skipped: repair_duplicate_dir
        // _inode just needs the truthful current count, and a
        // BogusEntry repair (if one runs in the same pass) will fix
        // the dirent byte separately.
        if matches!(e.file_type, DirEntryType::Directory) {
            if let Ok((child_inode, _)) = fs.read_inode_verified(e.inode) {
                if child_inode.is_dir() {
                    n = n.saturating_add(1);
                }
            }
        }
    }
    Ok(n)
}

/// Repair a link-count mismatch by writing `observed` into
/// `i_links_count`. Stays narrow on purpose — anything that needs more
/// surgery (e.g. observed == 0 should trigger the dead-inode reaping
/// path, not a 0 link count) is left as a TODO and the audit still
/// reports the underlying anomaly.
fn repair_link_count(
    fs: &Filesystem,
    ino: u32,
    observed: u32,
    report: &mut AuditReport,
) -> Result<()> {
    // Safety net: don't write 0 into i_links_count. A 0 nlink is the
    // contract for "this inode is unreachable, reaper will dispose of
    // it" — the right fix in that case is unlink+free, not a count
    // patch. Leave the anomaly as-is and let a future repair pass
    // (with orphan-relink wired up) handle it.
    if observed == 0 || observed > u16::MAX as u32 {
        // TODO: hook into orphan recovery for observed==0; for now,
        // surface the mismatch unchanged.
        return Ok(());
    }
    let (inode, mut raw) = fs.read_inode_verified(ino)?;
    raw[0x1A..0x1C].copy_from_slice(&(observed as u16).to_le_bytes());
    finalize_and_commit_inode(fs, ino, inode.generation, &mut raw)?;
    report.repaired_count += 1;
    Ok(())
}

/// Repair a `WrongDotDot` finding by rewriting the directory's ".."
/// dirent to point at `actual_parent`.
///
/// In ext4, a non-empty directory's ".." entry always lives in the
/// first data block (logical block 0) — the kernel writes it there at
/// directory creation time, immediately after the "." entry, and
/// nothing ever moves it. So we read just block 0, find the entry
/// with name "..", overwrite its 4-byte inode field, recompute the
/// per-block CRC tail (when metadata_csum is on), and commit through
/// the journal.
///
/// Out-of-scope cases that bail without bumping `repaired_count`:
/// - `dir_ino` is no longer a directory (raced delete during audit).
/// - Block 0 is unallocated (empty directory — ".." can't exist
///   without "."; treat as nothing-to-fix).
/// - The ".." entry isn't found in block 0 (corruption broader than
///   what this repair handles).
fn repair_wrong_dotdot(
    fs: &Filesystem,
    dir_ino: u32,
    actual_parent: u32,
    report: &mut AuditReport,
) -> Result<()> {
    let (dir_inode, _raw) = fs.read_inode_verified(dir_ino)?;
    if !dir_inode.is_dir() {
        return Ok(());
    }
    let bs = fs.sb.block_size();
    let Some(phys) = fs.map_inode_logical(&dir_inode, 0)? else {
        return Ok(());
    };
    let mut buf = BlockBuffer::new(bs);
    let block = buf.get_mut(fs, phys)?;
    let reserved_tail = if fs.csum.enabled && dir::has_csum_tail(block) {
        12
    } else {
        0
    };
    let usable_end = block.len().saturating_sub(reserved_tail);

    // Walk the dirent records in block 0. Same shape as the audit
    // walker uses, just inline so we can mutate in place.
    let mut off = 0usize;
    let mut found = false;
    while off + 8 <= usable_end {
        let rec_len = u16::from_le_bytes([block[off + 4], block[off + 5]]) as usize;
        if rec_len == 0 || off + rec_len > usable_end {
            break;
        }
        let name_len = block[off + 6] as usize;
        let name_start = off + 8;
        let name_end = name_start + name_len;
        if name_end <= off + rec_len && &block[name_start..name_end] == b".." {
            block[off..off + 4].copy_from_slice(&actual_parent.to_le_bytes());
            found = true;
            break;
        }
        off += rec_len;
    }
    if !found {
        return Ok(());
    }

    // Recompute the dir block CRC if metadata_csum reserved a tail.
    // Same recipe as repair_duplicate_dir_inode — see comments there.
    if fs.csum.enabled && reserved_tail == 12 {
        let end = block.len();
        let mut c = crate::checksum::linux_crc32c(fs.csum.seed, &dir_ino.to_le_bytes());
        c = crate::checksum::linux_crc32c(c, &dir_inode.generation.to_le_bytes());
        c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
        block[end - 4..end].copy_from_slice(&c.to_le_bytes());
    }

    fs.commit_block_buffer(buf)?;
    report.repaired_count += 1;
    Ok(())
}

/// Repair a `BogusEntry` finding by rewriting the parent dirent's
/// `file_type` byte to match the child inode's actual mode bits.
///
/// The audit emits this when a parent's dirent claims its child is a
/// directory (`file_type == 2`) but the child's inode mode bits say
/// otherwise. The on-disk fix in the common case is one byte: change
/// the dirent's `file_type` to whatever the child actually is (regular
/// file, symlink, etc.). Same dir-block CRC recompute pattern as
/// `repair_wrong_dotdot`.
///
/// Out-of-scope cases that bail without bumping `repaired_count`
/// (audit will resurface on next pass):
/// - The FILETYPE incompat feature is off (the byte at offset 7 is
///   the high half of `name_len` rather than `file_type`; rewriting
///   would be silent corruption).
/// - The parent isn't a directory anymore (raced with rmdir).
/// - The child reads back AS a directory (raced with the audit; not
///   bogus anymore).
/// - The child is unreadable (proper handling needs unlink + orphan
///   accounting; left for a follow-up).
/// - The child's mode bits are zero or otherwise nonsensical.
fn repair_bogus_entry(
    fs: &Filesystem,
    parent_ino: u32,
    child_ino: u32,
    name: &[u8],
    report: &mut AuditReport,
) -> Result<()> {
    let has_ft = fs.sb.feature_incompat & features::Incompat::FILETYPE.bits() != 0;
    if !has_ft {
        return Ok(());
    }
    if name.is_empty() {
        // Defensive: detection always populates `name` for non-root
        // BogusEntry findings. An empty name would mean "first match
        // by inode," which is exactly the hardlink-ambiguity bug we
        // moved away from. Bail rather than risk patching the wrong
        // dirent.
        return Ok(());
    }

    let (parent_inode, _parent_raw) = fs.read_inode_verified(parent_ino)?;
    if !parent_inode.is_dir() {
        return Ok(());
    }

    // Read the child to determine its actual file_type. If it's
    // genuinely unreadable or genuinely a directory, bail.
    let child_filetype: DirEntryType = match fs.read_inode_verified(child_ino) {
        Ok((child_inode, _)) => {
            let mode_bits = child_inode.mode & crate::inode::S_IFMT;
            match mode_bits {
                crate::inode::S_IFREG => DirEntryType::RegFile,
                crate::inode::S_IFDIR => return Ok(()),
                crate::inode::S_IFLNK => DirEntryType::Symlink,
                crate::inode::S_IFBLK => DirEntryType::BlockDev,
                crate::inode::S_IFCHR => DirEntryType::CharDev,
                crate::inode::S_IFIFO => DirEntryType::Fifo,
                crate::inode::S_IFSOCK => DirEntryType::Socket,
                _ => return Ok(()),
            }
        }
        Err(_) => return Ok(()),
    };

    // Walk parent dir blocks to find the dirent matching BOTH
    // (inode == child_ino) AND (name == this finding's name). The
    // (parent, name) pair is the unique key for a dirent — matching
    // by inode alone misfires when the parent has multiple hardlinks
    // to the same inode.
    let bs = fs.sb.block_size();
    let parent_blocks = parent_inode.size.div_ceil(bs as u64);
    let mut buf = BlockBuffer::new(bs);
    let mut found = false;
    for logical in 0..parent_blocks {
        let Some(phys) = fs.map_inode_logical(&parent_inode, logical)? else {
            continue;
        };
        let block = buf.get_mut(fs, phys)?;
        let reserved_tail = if fs.csum.enabled && dir::has_csum_tail(block) {
            12
        } else {
            0
        };
        let usable_end = block.len().saturating_sub(reserved_tail);
        let mut off = 0usize;
        let mut hit_off: Option<usize> = None;
        while off + 8 <= usable_end {
            let cur_inode =
                u32::from_le_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
            let rec_len = u16::from_le_bytes([block[off + 4], block[off + 5]]) as usize;
            if rec_len == 0 || off + rec_len > usable_end {
                break;
            }
            // FILETYPE feature is on (we bailed otherwise above), so
            // byte 6 is the full name_len; byte 7 is file_type.
            // Bound name comparison to the current record (8 +
            // name_len <= rec_len) so a malformed dirent with
            // name_len > rec_len can't read into the next record and
            // patch the wrong file_type byte.
            let name_len = block[off + 6] as usize;
            if cur_inode == child_ino
                && 8 + name_len <= rec_len
                && off + 8 + name_len <= usable_end
                && &block[off + 8..off + 8 + name_len] == name
            {
                hit_off = Some(off);
                break;
            }
            off += rec_len;
        }
        if let Some(off) = hit_off {
            block[off + 7] = child_filetype as u8;
            if fs.csum.enabled && reserved_tail == 12 {
                let end = block.len();
                let mut c = crate::checksum::linux_crc32c(fs.csum.seed, &parent_ino.to_le_bytes());
                c = crate::checksum::linux_crc32c(c, &parent_inode.generation.to_le_bytes());
                c = crate::checksum::linux_crc32c(c, &block[..end - 12]);
                block[end - 4..end].copy_from_slice(&c.to_le_bytes());
            }
            found = true;
            break;
        }
    }

    if found {
        fs.commit_block_buffer(buf)?;
        report.repaired_count += 1;
    }
    Ok(())
}

/// Repair a `BlockGroupFreeCountDrift` finding by patching the
/// descriptor's free-block / free-inode counters to match the bitmap
/// reality. Reuses `Filesystem::patch_bgd_counters` (the same path the
/// allocator already uses for live counter updates), which handles
/// the lo+hi 64-bit fields and recomputes the GD checksum when
/// `metadata_csum` is on.
fn repair_block_group_free_counts(
    fs: &Filesystem,
    group_index: u32,
    stored_blocks: u32,
    observed_blocks: u32,
    stored_inodes: u32,
    observed_inodes: u32,
    report: &mut AuditReport,
) -> Result<()> {
    let block_delta = (observed_blocks as i64) - (stored_blocks as i64);
    let inode_delta = (observed_inodes as i64) - (stored_inodes as i64);
    if block_delta == 0 && inode_delta == 0 {
        // Nothing to do; raced with another writer or audit was wrong.
        return Ok(());
    }
    if block_delta < i32::MIN as i64
        || block_delta > i32::MAX as i64
        || inode_delta < i32::MIN as i64
        || inode_delta > i32::MAX as i64
    {
        // Drift larger than i32 in a single group is implausible (a
        // group's blocks_per_group is bounded by 8 * block_size, which
        // tops out around 32k for 4 KiB blocks). Bail rather than
        // truncate.
        return Ok(());
    }
    fs.patch_bgd_counters(
        group_index as usize,
        block_delta as i32,
        inode_delta as i32,
        0,
    )?;
    report.repaired_count += 1;
    Ok(())
}

/// Repair a `SuperblockFreeCountDrift` finding by patching the
/// superblock totals. Reuses `Filesystem::patch_sb_counters` so the SB
/// checksum is recomputed on metadata_csum images.
fn repair_superblock_free_counts(
    fs: &Filesystem,
    stored_blocks: u64,
    observed_blocks: u64,
    stored_inodes: u32,
    observed_inodes: u32,
    report: &mut AuditReport,
) -> Result<()> {
    let block_delta = (observed_blocks as i64) - (stored_blocks as i64);
    let inode_delta = (observed_inodes as i64) - (stored_inodes as i64);
    if block_delta == 0 && inode_delta == 0 {
        return Ok(());
    }
    if inode_delta < i32::MIN as i64 || inode_delta > i32::MAX as i64 {
        return Ok(());
    }
    fs.patch_sb_counters(block_delta, inode_delta as i32)?;
    report.repaired_count += 1;
    Ok(())
}

/// Recompute the inode's CRC32C (when enabled) and commit the inode
/// back through the journal writer. Inode-only mutations get a single
/// journal txn — matches how `commit_inode_write` does chmod / chown.
fn finalize_and_commit_inode(
    fs: &Filesystem,
    ino: u32,
    generation: u32,
    raw: &mut [u8],
) -> Result<()> {
    if fs.csum.enabled {
        if let Some((lo, hi)) = fs.csum.compute_inode_checksum(ino, generation, raw) {
            raw[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
            if raw.len() >= 0x84 {
                raw[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
            }
        }
    }
    let mut buf = BlockBuffer::new(fs.sb.block_size());
    fs.buffer_write_inode(&mut buf, ino, raw)?;
    fs.commit_block_buffer(buf)
}

impl Filesystem {
    /// Run an ext4 audit tool-style read-only audit.
    ///
    /// Walks from root, counts how many directory entries reference
    /// each inode, and compares that against each inode's
    /// `i_links_count`. Returns an [`AuditReport`] — empty
    /// `anomalies` means every invariant we check held.
    ///
    /// The pass is bounded: never visits more than
    /// `max_dirs_visited` directories and never scans more than
    /// `max_entries_per_dir` entries within a single directory.
    /// Pass `u32::MAX` for an unbounded pass.
    pub fn audit(&self, max_dirs_visited: u32, max_entries_per_dir: u32) -> Result<AuditReport> {
        audit(self, max_dirs_visited, max_entries_per_dir)
    }

    /// Audit + repair convenience wrapper. See [`audit_with_repair`]
    /// for semantics. No-op on read-only mounts when `repair == true`
    /// (returns `Error::ReadOnly`).
    pub fn audit_repair(
        &self,
        max_dirs_visited: u32,
        max_entries_per_dir: u32,
        repair: bool,
    ) -> Result<AuditReport> {
        audit_with_repair(
            self,
            max_dirs_visited,
            max_entries_per_dir,
            |_, _, _| {},
            |_| {},
            repair,
        )
    }
}
