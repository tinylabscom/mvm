//! Segment layout: one on-disk file carries many logical chunks.
//!
//! The writer used to emit one file per pushed chunk. For a forensic capture
//! of a few hundred discrete frames that is fine; for a workload's continuous
//! output it makes the chunk cap an inode cap, and the cap has to be set low
//! enough that under a second of log output exhausts it.
//!
//! A **segment** is an append-only run of chunk ciphertexts in one file. A
//! [`ChunkRecord`] still addresses one *logical* chunk — it names the segment
//! holding it, its byte offset inside that segment, its own ciphertext length,
//! and the sha256 of its own ciphertext — so the sealed root commits to
//! exactly what it committed to before, and verification still catches a
//! single tampered chunk sharing a file with intact ones. Only the file layout
//! changed.
//!
//! Segments roll on ciphertext size or chunk count, never on elapsed time. A
//! record's `file` and `offset` are inside the sealed root, so a wall-clock
//! roll would give two captures of the same byte stream two different roots.
//!
//! Retention evicts whole segments, oldest first, and never the segment
//! currently being appended to. That is the granularity the store can actually
//! free — bytes in the middle of an append-only file cannot be reclaimed
//! without rewriting it — and keeping the active segment means the newest
//! write always lands.
//!
//! So a capture's durable window is only as fine-grained as the ratio of its
//! own bounds to a segment. On the chunk side the shipped stream budget of
//! 65 536 chunks against [`SEGMENT_MAX_CHUNKS`] is 64:1 — one eviction step
//! costs a sixty-fourth of the window. **The byte side is much tighter**: 8 MiB
//! of plaintext against a 1 MiB ciphertext segment is roughly 8:1, so a
//! workload pushing chunks large enough to hit the size trigger loses about an
//! eighth of its durable window per step. Below that the behaviour degenerates:
//! a `max_bytes` under [`SEGMENT_MAX_CIPHERTEXT_BYTES`] cannot hold even one
//! full segment plus the active one, so the live set oscillates between a
//! single chunk and a single segment. A caller wanting a window that tight
//! needs the segment size lowered with it, not just the bound.

use std::collections::{BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{CaptureBounds, ChunkRecord, Evicted, TranscriptError};

/// Ciphertext bytes one segment holds before the next chunk opens a new file.
pub const SEGMENT_MAX_CIPHERTEXT_BYTES: u64 = 1 << 20;

/// Chunks one segment holds before the next chunk opens a new file.
pub const SEGMENT_MAX_CHUNKS: u64 = 1024;

/// Scratch buffer for streaming one chunk's byte range through sha256, so a
/// manifest declaring an absurd `size_bytes` cannot make the verifier
/// allocate on its say-so.
const HASH_SCRATCH_BYTES: usize = 64 * 1024;

/// When a segment rolls. Both triggers are content-derived, so the same input
/// stream always produces the same layout and therefore the same sealed root.
///
/// Deliberately not public. A record's `file` and `offset` are inside the
/// sealed root, so these thresholds decide what the root commits to: exposing
/// them as a caller knob would give two captures of the same byte stream two
/// different roots depending on a config value. The layout is a property of
/// the format, not of the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SegmentBounds {
    pub max_ciphertext_bytes: u64,
    pub max_chunks: u64,
}

impl Default for SegmentBounds {
    fn default() -> Self {
        Self {
            max_ciphertext_bytes: SEGMENT_MAX_CIPHERTEXT_BYTES,
            max_chunks: SEGMENT_MAX_CHUNKS,
        }
    }
}

/// Where one appended chunk landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChunkPlacement {
    pub file: String,
    pub offset: u64,
}

/// One segment's running totals. Plaintext is tracked alongside ciphertext
/// because [`CaptureBounds`] counts plaintext (so `refused_bytes` and
/// `evicted_bytes` are the same unit) while the file layout counts the
/// ciphertext actually on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    file: String,
    chunks: u64,
    ciphertext_bytes: u64,
    plaintext_bytes: u64,
}

/// Filename for the `index`-th segment of a capture. Indices are never
/// reused, so an evicted segment's name cannot be resurrected by a later one.
fn segment_file_name(index: u64) -> String {
    format!("{index}.seg")
}

/// The append-only chunk store behind a transcript writer.
pub(crate) struct SegmentStore {
    dir: PathBuf,
    bounds: SegmentBounds,
    /// Segments closed to further appends, oldest first. Ring eviction
    /// unlinks from this front.
    sealed: VecDeque<Segment>,
    /// The segment being appended to. Never evicted: with nothing sealed left
    /// to free, refusing the newest write is the one outcome a stream capture
    /// must not have.
    active: Option<Segment>,
    next_index: u64,
}

impl SegmentStore {
    pub(crate) fn new(dir: PathBuf, bounds: SegmentBounds) -> Self {
        Self {
            dir,
            bounds,
            sealed: VecDeque::new(),
            active: None,
            next_index: 0,
        }
    }

    /// Append one chunk's ciphertext, opening a fresh segment first when the
    /// active one is full. `plaintext_len` is carried for retention
    /// accounting only.
    pub(crate) fn append(
        &mut self,
        ciphertext: &[u8],
        plaintext_len: u64,
    ) -> Result<ChunkPlacement, TranscriptError> {
        let width = ciphertext.len() as u64;
        self.roll_if_full(width);
        self.roll_if_disturbed();

        let placement = match &self.active {
            Some(active) => ChunkPlacement {
                file: active.file.clone(),
                offset: active.ciphertext_bytes,
            },
            None => ChunkPlacement {
                file: segment_file_name(self.next_index),
                offset: 0,
            },
        };
        self.write_at(&placement, ciphertext)?;
        self.count_append(&placement, width, plaintext_len);
        Ok(placement)
    }

    /// Unlink whole sealed segments, oldest first, until one more chunk of
    /// `plaintext_len` fits `bounds`. Reports what went so the caller can drop
    /// the matching records and declare the gap.
    pub(crate) fn evict_for(&mut self, plaintext_len: u64, bounds: CaptureBounds) -> Evicted {
        let mut evicted = Evicted::default();
        while self.would_exceed(plaintext_len, bounds) {
            let Some(oldest) = self.sealed.pop_front() else {
                break; // only the active segment is left, and it never goes
            };
            // Best effort: the records go either way, so a file that refuses
            // to unlink leaves a stray file, never a chunk the manifest still
            // claims but cannot produce.
            let _ = std::fs::remove_file(self.dir.join(&oldest.file));
            evicted.chunks = evicted.chunks.saturating_add(oldest.chunks);
            evicted.bytes = evicted.bytes.saturating_add(oldest.plaintext_bytes);
        }
        evicted
    }

    /// Chunks still held on disk.
    pub(crate) fn live_chunks(&self) -> u64 {
        self.fold_live(|s| s.chunks)
    }

    /// Plaintext bytes behind the chunks still held on disk.
    pub(crate) fn live_plaintext_bytes(&self) -> u64 {
        self.fold_live(|s| s.plaintext_bytes)
    }

    /// Files this store currently owns — the number retention actually bounds.
    pub(crate) fn segment_count(&self) -> usize {
        self.sealed.len() + usize::from(self.active.is_some())
    }

    fn fold_live(&self, of: impl Fn(&Segment) -> u64) -> u64 {
        self.sealed
            .iter()
            .chain(self.active.iter())
            .fold(0u64, |total, segment| total.saturating_add(of(segment)))
    }

    fn would_exceed(&self, plaintext_len: u64, bounds: CaptureBounds) -> bool {
        self.live_plaintext_bytes().saturating_add(plaintext_len) > bounds.max_bytes
            || self.live_chunks().saturating_add(1) > bounds.max_chunks
    }

    /// Close the active segment when one more chunk would overflow it. An
    /// active segment always holds at least one chunk, so an oversized chunk
    /// gets a segment to itself instead of rolling forever.
    fn roll_if_full(&mut self, incoming_ciphertext: u64) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let overflows = active.ciphertext_bytes.saturating_add(incoming_ciphertext)
            > self.bounds.max_ciphertext_bytes
            || active.chunks.saturating_add(1) > self.bounds.max_chunks;
        if overflows {
            self.close_active();
        }
    }

    /// Handle an active segment that is no longer the length this store left
    /// it — deleted out from under the capture, torn short, or carrying bytes
    /// past the last record.
    ///
    /// *Short or missing* is unrecoverable: bytes the manifest already commits
    /// to are gone, and appending regardless would place every later chunk at
    /// an offset that does not describe its bytes, quietly corrupting records
    /// that verify today. Refusing forever is the other wrong answer — a store
    /// that hiccups once would silence the workload for the rest of its life,
    /// which is the failure this whole path exists to remove. So the segment
    /// is abandoned where it is, its records still point at it,
    /// [`verify_segments`] reports the discrepancy, and the capture carries on
    /// in a fresh file.
    ///
    /// *Long* is the repairable case, and the common one: an append that died
    /// partway leaves the bytes that fit behind a chunk whose record was
    /// refused. Nothing accounts for that tail, so the sealed root loses
    /// nothing when it goes — whereas abandoning over it strands a span
    /// `verify_chunks` refuses for the life of the capture, taking every
    /// intact segment in the same manifest down with it. One full disk must
    /// not cost the whole artifact.
    fn roll_if_disturbed(&mut self) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let accounted = active.ciphertext_bytes;
        match self.on_disk_len(&active.file) {
            Some(len) if len == accounted => {}
            Some(len) if len > accounted => self.drop_unaccounted_tail(accounted),
            _ => self.close_active(),
        }
    }

    /// Cut bytes no record accounts for off the end of the active segment,
    /// abandoning it only if even that fails.
    fn drop_unaccounted_tail(&mut self, accounted: u64) {
        let Some(active) = self.active.as_ref() else {
            return;
        };
        let repaired = OpenOptions::new()
            .write(true)
            .open(self.dir.join(&active.file))
            .and_then(|handle| handle.set_len(accounted))
            .is_ok();
        if !repaired {
            self.close_active();
        }
    }

    fn on_disk_len(&self, file: &str) -> Option<u64> {
        std::fs::metadata(self.dir.join(file)).ok().map(|m| m.len())
    }

    /// Stop appending to the current segment, keeping it in the eviction
    /// order so retention can still reclaim it.
    fn close_active(&mut self) {
        if let Some(closed) = self.active.take() {
            self.sealed.push_back(closed);
        }
    }

    /// Put the bytes on disk at exactly the offset the record will claim, or
    /// leave the segment exactly as it was.
    ///
    /// A segment's first chunk truncates: a stale file left behind by a
    /// crashed capture would otherwise shift every offset this manifest
    /// records. Later chunks append onto a file [`roll_if_disturbed`] has
    /// just confirmed is the length this store left it.
    ///
    /// [`roll_if_disturbed`]: Self::roll_if_disturbed
    fn write_at(
        &self,
        placement: &ChunkPlacement,
        ciphertext: &[u8],
    ) -> Result<(), TranscriptError> {
        let mut options = OpenOptions::new();
        options.create(true);
        if placement.offset == 0 {
            options.write(true).truncate(true);
        } else {
            options.append(true);
        }
        let io = |e: std::io::Error| TranscriptError::Io {
            file: placement.file.clone(),
            msg: e.to_string(),
        };
        let mut handle = options.open(self.dir.join(&placement.file)).map_err(io)?;
        if let Err(e) = handle.write_all(ciphertext) {
            roll_back_to(&handle, placement.offset);
            return Err(io(e));
        }
        Ok(())
    }

    /// Charge a landed chunk to its segment, opening one if this was the first.
    fn count_append(&mut self, placement: &ChunkPlacement, width: u64, plaintext_len: u64) {
        match self.active.as_mut() {
            Some(active) => {
                active.chunks = active.chunks.saturating_add(1);
                active.ciphertext_bytes = active.ciphertext_bytes.saturating_add(width);
                active.plaintext_bytes = active.plaintext_bytes.saturating_add(plaintext_len);
            }
            None => {
                self.next_index = self.next_index.saturating_add(1);
                self.active = Some(Segment {
                    file: placement.file.clone(),
                    chunks: 1,
                    ciphertext_bytes: width,
                    plaintext_bytes: plaintext_len,
                });
            }
        }
    }
}

/// Cut a failed append back off a segment, so the file is again the length
/// the manifest accounts for.
///
/// A `write_all` that dies partway — a full disk is the realistic cause —
/// still leaves the bytes that fit. The chunk's record is refused, so nothing
/// accounts for those bytes, and a capture that seals right afterwards has no
/// later append to notice. Undoing it here is what keeps such a capture
/// verifiable. Best effort: if the rollback itself fails, the next append's
/// [`SegmentStore::roll_if_disturbed`] finds the same overlong file and
/// repairs it there instead.
fn roll_back_to(handle: &File, offset: u64) {
    let _ = handle.set_len(offset);
}

/// One segment's worth of consecutive chunk records, with the exact byte count
/// they account for.
pub(crate) struct SegmentSpan<'a> {
    pub file: &'a str,
    pub chunks: &'a [ChunkRecord],
    pub bytes: u64,
}

/// Group `chunks` into the segments holding them, proving as it goes that the
/// records tile each segment exactly.
///
/// Tiling — first offset zero, every later offset flush against its
/// predecessor, and (checked by [`verify_segments`]) the file no longer than
/// the run — is what makes "no unaccounted ciphertext in the store" a
/// verified property rather than a convention. Without it a manifest could
/// leave gaps holding bytes nothing commits to, or overlap two records onto
/// the same bytes.
pub(crate) fn segment_spans(
    chunks: &[ChunkRecord],
) -> Result<Vec<SegmentSpan<'_>>, TranscriptError> {
    let mut spans: Vec<SegmentSpan<'_>> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut open: Option<&str> = None;
    let mut start = 0usize;
    let mut offset = 0u64;

    for (index, chunk) in chunks.iter().enumerate() {
        check_safe_name(&chunk.file)?;
        if open != Some(chunk.file.as_str()) {
            if open.is_some() {
                push_span(&mut spans, chunks, start, index, offset);
            }
            if !seen.insert(chunk.file.as_str()) {
                return Err(TranscriptError::SegmentRepeated {
                    file: chunk.file.clone(),
                });
            }
            open = Some(chunk.file.as_str());
            start = index;
            offset = 0;
        }
        if chunk.offset != offset {
            return Err(TranscriptError::SegmentLayoutInvalid {
                seq: chunk.seq,
                file: chunk.file.clone(),
                offset: chunk.offset,
                expected: offset,
            });
        }
        offset = offset.checked_add(chunk.size_bytes).ok_or_else(|| {
            TranscriptError::SegmentLayoutInvalid {
                seq: chunk.seq,
                file: chunk.file.clone(),
                offset: chunk.offset,
                expected: offset,
            }
        })?;
    }
    if open.is_some() {
        push_span(&mut spans, chunks, start, chunks.len(), offset);
    }
    Ok(spans)
}

fn push_span<'a>(
    spans: &mut Vec<SegmentSpan<'a>>,
    chunks: &'a [ChunkRecord],
    start: usize,
    end: usize,
    bytes: u64,
) {
    let run = &chunks[start..end];
    if let Some(first) = run.first() {
        spans.push(SegmentSpan {
            file: first.file.as_str(),
            chunks: run,
            bytes,
        });
    }
}

/// Verify every chunk against the segment holding it.
///
/// Segment length is checked before any chunk is hashed, so a capture torn
/// mid-write reports an honest short segment instead of a hash mismatch that
/// reads like tampering. Then each chunk's own byte range is streamed through
/// sha256 and compared with its own recorded digest — the per-chunk integrity
/// the one-file-per-chunk layout had, unchanged.
pub(crate) fn verify_segments(chunks: &[ChunkRecord], dir: &Path) -> Result<(), TranscriptError> {
    for span in segment_spans(chunks)? {
        let path = dir.join(span.file);
        let anchor_seq = span.chunks.first().map(|c| c.seq).unwrap_or_default();
        let actual = std::fs::metadata(&path)
            .map_err(|_| TranscriptError::MissingChunk {
                seq: anchor_seq,
                file: span.file.to_string(),
            })?
            .len();
        if actual != span.bytes {
            return Err(TranscriptError::SegmentLengthMismatch {
                file: span.file.to_string(),
                declared: span.bytes,
                actual,
            });
        }
        let mut handle = File::open(&path).map_err(|e| TranscriptError::Io {
            file: span.file.to_string(),
            msg: e.to_string(),
        })?;
        for chunk in span.chunks {
            let got = hash_range(&mut handle, chunk)?;
            if got != chunk.sha256_hex {
                return Err(TranscriptError::HashMismatch {
                    seq: chunk.seq,
                    file: chunk.file.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Stream one chunk's byte range through sha256, without holding it all.
fn hash_range(handle: &mut File, chunk: &ChunkRecord) -> Result<String, TranscriptError> {
    let io = |e: std::io::Error| TranscriptError::Io {
        file: chunk.file.clone(),
        msg: e.to_string(),
    };
    handle.seek(SeekFrom::Start(chunk.offset)).map_err(io)?;
    let mut hasher = Sha256::new();
    let mut scratch = [0u8; HASH_SCRATCH_BYTES];
    let mut left = chunk.size_bytes;
    while left > 0 {
        let want = left.min(HASH_SCRATCH_BYTES as u64) as usize;
        handle.read_exact(&mut scratch[..want]).map_err(io)?;
        hasher.update(&scratch[..want]);
        left -= want as u64;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Slice one chunk's ciphertext out of its already-read segment.
pub(crate) fn slice_chunk<'a>(
    segment: &'a [u8],
    chunk: &ChunkRecord,
) -> Result<&'a [u8], TranscriptError> {
    let start = usize::try_from(chunk.offset).unwrap_or(usize::MAX);
    let end = usize::try_from(chunk.offset.saturating_add(chunk.size_bytes)).unwrap_or(usize::MAX);
    segment
        .get(start..end)
        .ok_or_else(|| TranscriptError::SegmentLengthMismatch {
            file: chunk.file.clone(),
            declared: chunk.offset.saturating_add(chunk.size_bytes),
            actual: segment.len() as u64,
        })
}

/// Reject anything that is not a plain filename inside the capture dir.
fn check_safe_name(file: &str) -> Result<(), TranscriptError> {
    if file.is_empty() || file.contains('/') || file.contains('\\') || file == "." || file == ".." {
        return Err(TranscriptError::UnsafeChunkName(file.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::Direction;

    fn tight_bounds() -> SegmentBounds {
        SegmentBounds {
            max_ciphertext_bytes: 32,
            max_chunks: 3,
        }
    }

    fn capture_bounds(max_bytes: u64, max_chunks: u64) -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes,
            max_chunks,
        }
    }

    fn record(seq: u64, file: &str, offset: u64, body: &[u8]) -> ChunkRecord {
        ChunkRecord {
            seq,
            file: file.to_string(),
            offset,
            sha256_hex: hex::encode(Sha256::digest(body)),
            size_bytes: body.len() as u64,
            direction: Direction::Stdout,
            dropped: false,
            prev_hash: "0".repeat(64),
        }
    }

    #[test]
    fn many_chunks_share_one_segment_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), SegmentBounds::default());
        for _ in 0..500 {
            store.append(b"chunk", 5).expect("append");
        }
        assert_eq!(store.segment_count(), 1, "500 chunks, one file");
        assert_eq!(store.live_chunks(), 500);
    }

    #[test]
    fn a_segment_rolls_on_its_chunk_count() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), tight_bounds());
        for _ in 0..7 {
            store.append(b"ab", 2).expect("append");
        }
        // 3 per segment: 3 + 3 + 1.
        assert_eq!(store.segment_count(), 3);
    }

    #[test]
    fn a_segment_rolls_on_its_byte_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(
            dir.path().to_path_buf(),
            SegmentBounds {
                max_ciphertext_bytes: 10,
                max_chunks: u64::MAX,
            },
        );
        for _ in 0..6 {
            store.append(b"abcd", 4).expect("append");
        }
        // 8 bytes fit, 12 would not: two chunks per segment.
        assert_eq!(store.segment_count(), 3);
    }

    #[test]
    fn a_chunk_wider_than_a_whole_segment_gets_one_to_itself() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), tight_bounds());
        store.append(b"small", 5).expect("append small");
        let placement = store.append(&[7u8; 4096], 4096).expect("append huge");
        assert_eq!(placement.offset, 0, "the oversized chunk opened its own");
        assert_eq!(store.segment_count(), 2);
    }

    #[test]
    fn appended_offsets_tile_the_segment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), SegmentBounds::default());
        let first = store.append(b"aaa", 3).expect("first");
        let second = store.append(b"bbbb", 4).expect("second");
        assert_eq!(first.offset, 0);
        assert_eq!(second.offset, 3);
        assert_eq!(first.file, second.file);
        let on_disk = std::fs::read(dir.path().join(&first.file)).expect("segment");
        assert_eq!(on_disk, b"aaabbbb");
    }

    #[test]
    fn a_fresh_segment_truncates_a_stale_file_rather_than_shifting_offsets() {
        // A crashed capture can leave `0.seg` behind. Appending onto it would
        // put every recorded offset a few bytes off its real bytes.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("0.seg"), b"leftover").expect("stale file");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), SegmentBounds::default());
        let placement = store.append(b"real", 4).expect("append");
        assert_eq!(placement.offset, 0);
        assert_eq!(
            std::fs::read(dir.path().join(&placement.file)).expect("segment"),
            b"real"
        );
    }

    /// Reproduce exactly what a `write_all` killed partway leaves behind: the
    /// bytes that fit, appended past the last record the store counted.
    fn leave_short_write_residue(dir: &Path, file: &str, residue: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(dir.join(file))
            .and_then(|mut handle| handle.write_all(residue))
            .expect("leave a partial write on disk");
    }

    #[test]
    fn a_truncated_segment_is_abandoned_rather_than_appended_to() {
        // Bytes the records already commit to are gone, so nothing can put
        // them back; appending would land the next chunk at a position no
        // record describes. Refusing forever would silence the capture over
        // one hiccup, so it moves on instead.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), SegmentBounds::default());
        let first = store.append(b"aaa", 3).expect("first");
        std::fs::write(dir.path().join(&first.file), b"a").expect("interference");

        let next = store.append(b"bbb", 3).expect("the capture carries on");
        assert_ne!(next.file, first.file, "in a fresh segment");
        assert_eq!(next.offset, 0);
        assert_eq!(
            std::fs::read(dir.path().join(&next.file)).expect("segment"),
            b"bbb"
        );
        // The disturbance is still discoverable: the records for the old
        // segment no longer describe it.
        let stale = vec![record(0, &first.file, 0, b"aaa")];
        assert!(matches!(
            verify_segments(&stale, dir.path()),
            Err(TranscriptError::SegmentLengthMismatch { .. })
        ));
    }

    #[test]
    fn a_short_write_does_not_poison_the_rest_of_the_capture() {
        // One ENOSPC must not cost the artifact. Abandoning over the leftover
        // bytes would strand a span `verify_chunks` refuses forever — and it
        // refuses the whole manifest, so every intact segment either side goes
        // with it.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), SegmentBounds::default());
        let first = store.append(b"aaa", 3).expect("first");
        leave_short_write_residue(dir.path(), &first.file, b"PARTIAL");

        let next = store.append(b"bbb", 3).expect("the capture carries on");
        assert_eq!(next.file, first.file, "in the same segment");
        assert_eq!(next.offset, 3, "the unaccounted tail is gone");
        assert_eq!(
            std::fs::read(dir.path().join(&next.file)).expect("segment"),
            b"aaabbb"
        );
        let chunks = vec![
            record(0, &first.file, 0, b"aaa"),
            record(1, &next.file, 3, b"bbb"),
        ];
        verify_segments(&chunks, dir.path()).expect("the capture still verifies");
    }

    #[test]
    fn rolling_a_failed_append_back_leaves_only_the_accounted_bytes() {
        // The immediate half of the repair: a capture that seals right after a
        // failed write has no later append to fix the file for it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("0.seg");
        std::fs::write(&path, b"aaaPARTIAL").expect("residue of a short write");
        let handle = OpenOptions::new().append(true).open(&path).expect("open");
        roll_back_to(&handle, 3);
        assert_eq!(std::fs::read(&path).expect("segment"), b"aaa");
    }

    #[test]
    fn a_segment_deleted_out_from_under_the_store_does_not_wedge_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), SegmentBounds::default());
        let first = store.append(b"aaa", 3).expect("first");
        std::fs::remove_file(dir.path().join(&first.file)).expect("delete the segment");

        let next = store.append(b"bbb", 3).expect("the capture recovers");
        assert_ne!(next.file, first.file);
        assert_eq!(next.offset, 0);
    }

    #[test]
    fn an_abandoned_segment_is_still_reclaimable_by_retention() {
        // Abandoning must not drop a segment out of the eviction order, or the
        // ring would stop charging for records the manifest still carries.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), SegmentBounds::default());
        let first = store.append(b"aaa", 3).expect("first");
        std::fs::write(dir.path().join(&first.file), b"a").expect("interference");
        store.append(b"bbb", 3).expect("second");
        assert_eq!(store.live_chunks(), 2);

        let evicted = store.evict_for(3, capture_bounds(u64::MAX, 1));
        assert_eq!(evicted.chunks, 1, "the abandoned segment is evictable");
        assert_eq!(store.live_chunks(), 1);
    }

    #[test]
    fn eviction_unlinks_whole_sealed_segments_oldest_first() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), tight_bounds());
        for _ in 0..9 {
            store.append(b"ab", 2).expect("append");
        }
        assert_eq!(store.segment_count(), 3);
        // Room for 4 chunks total: two whole segments must go.
        let evicted = store.evict_for(2, capture_bounds(u64::MAX, 4));
        assert_eq!(evicted.chunks, 6);
        assert_eq!(evicted.bytes, 12);
        assert!(!dir.path().join("0.seg").exists());
        assert!(!dir.path().join("1.seg").exists());
        assert!(dir.path().join("2.seg").exists());
    }

    #[test]
    fn eviction_never_takes_the_active_segment() {
        // The newest write always wins: with nothing sealed left to free, the
        // store admits rather than refusing.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), SegmentBounds::default());
        store.append(b"only", 4).expect("append");
        let evicted = store.evict_for(4, capture_bounds(1, 1));
        assert_eq!(evicted, Evicted::default());
        assert_eq!(store.segment_count(), 1);
    }

    #[test]
    fn an_evicted_segment_index_is_never_reused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = SegmentStore::new(dir.path().to_path_buf(), tight_bounds());
        for _ in 0..4 {
            store.append(b"ab", 2).expect("append");
        }
        store.evict_for(2, capture_bounds(u64::MAX, 1));
        let placement = store.append(b"cd", 2).expect("append after eviction");
        assert_ne!(placement.file, "0.seg", "a freed name must not come back");
    }

    #[test]
    fn spans_group_consecutive_records_by_segment() {
        let chunks = vec![
            record(0, "0.seg", 0, b"aa"),
            record(1, "0.seg", 2, b"bbb"),
            record(2, "1.seg", 0, b"c"),
        ];
        let spans = segment_spans(&chunks).expect("spans");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].file, "0.seg");
        assert_eq!(spans[0].bytes, 5);
        assert_eq!(spans[1].bytes, 1);
    }

    #[test]
    fn a_gap_between_two_records_is_refused() {
        // Bytes no record accounts for are bytes the sealed root does not
        // commit to; they must not be able to sit in the store.
        let chunks = vec![record(0, "0.seg", 0, b"aa"), record(1, "0.seg", 9, b"bb")];
        assert!(matches!(
            segment_spans(&chunks),
            Err(TranscriptError::SegmentLayoutInvalid { seq: 1, .. })
        ));
    }

    #[test]
    fn two_records_over_the_same_bytes_are_refused() {
        let chunks = vec![record(0, "0.seg", 0, b"aa"), record(1, "0.seg", 1, b"bb")];
        assert!(matches!(
            segment_spans(&chunks),
            Err(TranscriptError::SegmentLayoutInvalid { seq: 1, .. })
        ));
    }

    #[test]
    fn a_segment_named_twice_is_refused() {
        let chunks = vec![
            record(0, "0.seg", 0, b"aa"),
            record(1, "1.seg", 0, b"bb"),
            record(2, "0.seg", 0, b"cc"),
        ];
        assert!(matches!(
            segment_spans(&chunks),
            Err(TranscriptError::SegmentRepeated { .. })
        ));
    }

    #[test]
    fn an_unsafe_segment_name_is_refused() {
        let chunks = vec![record(0, "../escape", 0, b"aa")];
        assert!(matches!(
            segment_spans(&chunks),
            Err(TranscriptError::UnsafeChunkName(_))
        ));
    }

    #[test]
    fn verification_passes_over_a_shared_segment() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("0.seg"), b"aabbb").expect("segment");
        let chunks = vec![record(0, "0.seg", 0, b"aa"), record(1, "0.seg", 2, b"bbb")];
        verify_segments(&chunks, dir.path()).expect("intact segment verifies");
    }

    #[test]
    fn one_tampered_chunk_inside_a_shared_segment_is_still_caught() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("0.seg"), b"aaXbb").expect("segment");
        let chunks = vec![record(0, "0.seg", 0, b"aa"), record(1, "0.seg", 2, b"bbb")];
        assert!(matches!(
            verify_segments(&chunks, dir.path()),
            Err(TranscriptError::HashMismatch { seq: 1, .. })
        ));
    }

    #[test]
    fn a_torn_segment_reports_a_short_file_not_a_hash_mismatch() {
        // A capture killed mid-append leaves a short last segment. Reading
        // that as tampering would blame an attacker for a power cut.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("0.seg"), b"aab").expect("torn segment");
        let chunks = vec![record(0, "0.seg", 0, b"aa"), record(1, "0.seg", 2, b"bbb")];
        assert_eq!(
            verify_segments(&chunks, dir.path()),
            Err(TranscriptError::SegmentLengthMismatch {
                file: "0.seg".to_string(),
                declared: 5,
                actual: 3,
            })
        );
    }

    #[test]
    fn bytes_appended_past_the_last_record_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("0.seg"), b"aabbbEXTRA").expect("segment");
        let chunks = vec![record(0, "0.seg", 0, b"aa"), record(1, "0.seg", 2, b"bbb")];
        assert!(matches!(
            verify_segments(&chunks, dir.path()),
            Err(TranscriptError::SegmentLengthMismatch { actual: 10, .. })
        ));
    }

    #[test]
    fn a_missing_segment_reports_the_first_chunk_it_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let chunks = vec![record(4, "0.seg", 0, b"aa")];
        assert!(matches!(
            verify_segments(&chunks, dir.path()),
            Err(TranscriptError::MissingChunk { seq: 4, .. })
        ));
    }

    #[test]
    fn slicing_refuses_a_range_past_the_end_of_the_segment() {
        let chunk = record(0, "0.seg", 4, b"aa");
        assert!(matches!(
            slice_chunk(b"abc", &chunk),
            Err(TranscriptError::SegmentLengthMismatch { .. })
        ));
    }

    #[test]
    fn a_chunk_longer_than_the_hash_scratch_buffer_hashes_correctly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let body = vec![0x5au8; HASH_SCRATCH_BYTES * 2 + 7];
        std::fs::write(dir.path().join("0.seg"), &body).expect("segment");
        let chunks = vec![record(0, "0.seg", 0, &body)];
        verify_segments(&chunks, dir.path()).expect("multi-buffer chunk verifies");
    }
}
