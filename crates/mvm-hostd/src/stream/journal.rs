//! The capture's manifest-in-progress, on disk, so a seal does not depend on
//! the process that opened the capture still being alive.
//!
//! A transcript seals from its [`TranscriptWriter`], and that writer lives in
//! the address space of whichever host process started the workload. For a
//! foreground run that is also the process that stops it, so the seal happens
//! and the run stays readable. For every other shape — a detached start, a
//! start whose caller was interrupted, a stop issued days later — the writer
//! is gone by the time anyone ends the VM, and a capture with no manifest is
//! a directory of ciphertext nobody can open.
//!
//! So the writer thread mirrors each landed chunk into an append-only journal
//! beside the segments. The journal is written by the same thread that does
//! the append and never by a producer, so it inherits the whole point of
//! [`super::durable`]: a slow disk costs the transcript records, never the
//! workload its pace.
//!
//! **The journal is a mirror, not a second source of truth.** A process that
//! still holds the writer always seals from the writer — the journal is only
//! read by [`replay`], and only for a capture whose owner is gone.
//!
//! **A replayed seal cannot claim completeness.** Records the departed
//! process shed at the hand-off after its last durable append are in no file
//! anywhere; nothing on disk can count them. That is what
//! `TranscriptManifest::adopted` is for, and [`replay`] always sets it.
//!
//! **Layout.** One JSON object per line. The first is the capture's own
//! chunkless manifest (binding, bounds, retention, wrapped data key); each
//! later one is a landed [`ChunkRecord`] plus the capture's running shortfall
//! at the moment it landed. Line-oriented because the only write that must be
//! atomic is a single append, and a torn final line — the shape a killed
//! process leaves — is then exactly one lost record rather than an unreadable
//! file.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use mvm_core::transcript::{ChunkRecord, TranscriptManifest, sealed_root_hex};
use serde::{Deserialize, Serialize};

/// The mirrored manifest, beside the segments it describes.
pub(in crate::stream) const JOURNAL_FILENAME: &str = "capture.jsonl";

/// How much of a capture never landed, as of one journal line.
///
/// Carried per line rather than once at the end because there is no end: the
/// journal's last line is whatever the owning process got to write before it
/// stopped existing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::stream) struct JournalShortfall {
    #[serde(default)]
    pub refused_chunks: u64,
    #[serde(default)]
    pub refused_bytes: u64,
    #[serde(default)]
    pub evicted_chunks: u64,
    #[serde(default)]
    pub evicted_bytes: u64,
}

/// One landed chunk, with the capture's shortfall at that point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalChunk {
    chunk: ChunkRecord,
    #[serde(flatten)]
    shortfall: JournalShortfall,
}

/// One journal line. Externally tagged so the payload types keep their own
/// `deny_unknown_fields`, which an internal tag would break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalLine {
    /// The capture's chunkless manifest, written once before any chunk.
    Header(Box<TranscriptManifest>),
    Chunk(Box<JournalChunk>),
}

/// The append-only mirror of one capture's manifest.
///
/// Opened on the first chunk rather than at construction: the plane clears a
/// restarted VM's capture directory after it has claimed the VM's socket, and
/// a file created before that point would be unlinked out from under a handle
/// that then writes into nothing.
pub(in crate::stream) struct CaptureJournal {
    path: PathBuf,
    /// The chunkless manifest written as the first line, taken before any
    /// chunk landed. Dropped once the header is on disk.
    header: Option<Box<TranscriptManifest>>,
    file: Option<File>,
    /// Set once opening or writing has failed, so a capture on a full disk
    /// logs one line rather than one per chunk. A journal that cannot be
    /// written costs the capture its cross-process seal and nothing else.
    broken: bool,
}

impl CaptureJournal {
    /// A journal for the capture `seed` describes, in `dir`.
    pub fn new(dir: &Path, seed: TranscriptManifest) -> Self {
        Self {
            path: dir.join(JOURNAL_FILENAME),
            header: Some(Box::new(seed)),
            file: None,
            broken: false,
        }
    }

    /// Mirror one landed chunk. Best-effort by contract: the transcript is
    /// already on disk either way, and the only thing a failure here costs is
    /// the ability to seal it from another process.
    pub fn record(&mut self, chunk: &ChunkRecord, shortfall: JournalShortfall) {
        if self.broken {
            return;
        }
        let line = JournalLine::Chunk(Box::new(JournalChunk {
            chunk: chunk.clone(),
            shortfall,
        }));
        if let Err(error) = self.append(&line) {
            self.broken = true;
            self.file = None;
            tracing::warn!(
                path = %self.path.display(),
                error = %error,
                "capture journal is not being written; this transcript can only be sealed by \
                 the process that opened it"
            );
        }
    }

    /// Delete the journal. Called once a manifest supersedes it, so a later
    /// reader cannot mistake a stale mirror for a capture in need of
    /// adoption.
    pub fn discard(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    /// This journal's path, for the caller that removes it after sealing.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append(&mut self, line: &JournalLine) -> std::io::Result<()> {
        if self.file.is_none() {
            self.open()?;
        }
        let file = self
            .file
            .as_mut()
            .expect("open() leaves a file handle or returns an error");
        let mut body = serde_json::to_vec(line)?;
        body.push(b'\n');
        file.write_all(&body)?;
        file.flush()
    }

    /// Create the file and write the header line into it.
    ///
    /// Truncating rather than appending: the plane discards a previous boot's
    /// capture before the first chunk of the new one, so anything found here
    /// belongs to a run whose segments are already gone.
    fn open(&mut self) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)?;
        let header = self
            .header
            .take()
            .expect("the header is written exactly once, on the first append");
        let mut body = serde_json::to_vec(&JournalLine::Header(header))?;
        body.push(b'\n');
        file.write_all(&body)?;
        self.file = Some(file);
        Ok(())
    }
}

/// A capture rebuilt from its journal, ready to seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::stream) struct ReplayedCapture {
    /// The manifest the departed writer would have produced, as far as its
    /// journal got — always carrying `adopted`.
    pub manifest: TranscriptManifest,
    /// Segment files and the byte length the manifest accounts for in each,
    /// so a caller can cut an interrupted append's residue off the end.
    pub declared_lengths: Vec<(String, u64)>,
}

/// Rebuild `dir`'s capture from its journal, or `None` when there is no
/// journal to rebuild from.
///
/// Lines that do not parse are skipped, not fatal: the last line of a journal
/// whose writer was killed mid-append is a partial one, and refusing the whole
/// capture over it would throw away every record before it.
pub(in crate::stream) fn replay(dir: &Path) -> Option<ReplayedCapture> {
    let file = File::open(dir.join(JOURNAL_FILENAME)).ok()?;
    let mut manifest: Option<TranscriptManifest> = None;
    let mut chunks: Vec<ChunkRecord> = Vec::new();
    let mut shortfall = JournalShortfall::default();

    for line in BufReader::new(file).lines().map_while(Result::ok) {
        match serde_json::from_str::<JournalLine>(&line) {
            Ok(JournalLine::Header(header)) => manifest = Some(*header),
            Ok(JournalLine::Chunk(entry)) => {
                chunks.push(entry.chunk);
                shortfall = entry.shortfall;
            }
            Err(_) => continue,
        }
    }

    let mut manifest = manifest?;
    // Eviction drops from the front, oldest first, and the journal records
    // every chunk that ever landed — so the surviving window is the tail, cut
    // to exactly what the writer's own deque held. Without this the manifest
    // would claim segments retention already unlinked.
    let evicted = usize::try_from(shortfall.evicted_chunks).unwrap_or(usize::MAX);
    let surviving = chunks.split_off(evicted.min(chunks.len()));

    manifest.chunks = surviving;
    manifest.refused_chunks = shortfall.refused_chunks;
    manifest.refused_bytes = shortfall.refused_bytes;
    manifest.evicted_chunks = shortfall.evicted_chunks;
    manifest.evicted_bytes = shortfall.evicted_bytes;
    // Always. Nothing on disk records what the departed process shed after
    // its last journalled chunk, so this manifest is a floor by construction.
    manifest.adopted = true;
    manifest.sealed_root_hex =
        sealed_root_hex(&manifest).expect("fixed transcript root metadata serializes");

    let declared_lengths = declared_lengths(&manifest.chunks);
    Some(ReplayedCapture {
        manifest,
        declared_lengths,
    })
}

/// How many bytes each segment holds according to the records that survived.
///
/// Records tile their segment, so the end of the last one is the whole of it.
fn declared_lengths(chunks: &[ChunkRecord]) -> Vec<(String, u64)> {
    let mut lengths: Vec<(String, u64)> = Vec::new();
    for chunk in chunks {
        let end = chunk.offset.saturating_add(chunk.size_bytes);
        match lengths.iter_mut().find(|(file, _)| file == &chunk.file) {
            Some((_, declared)) => *declared = (*declared).max(end),
            None => lengths.push((chunk.file.clone(), end)),
        }
    }
    lengths
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::transcript::{
        CaptureBinding, CaptureBounds, Direction, RetentionPolicy, TranscriptWriter,
        TranscriptWriterConfig, verify_sealed_root,
    };

    fn writer_at(dir: &Path) -> TranscriptWriter {
        TranscriptWriter::new(
            dir,
            mvm_core::crypto::aead::Key::from_bytes([0x21; 32]),
            TranscriptWriterConfig {
                capture_id: "capture-journal".to_string(),
                binding: CaptureBinding {
                    tenant_id: "local".to_string(),
                    vm_name: "vm-journal".to_string(),
                    session_id: None,
                },
                bounds: CaptureBounds {
                    max_duration_secs: u64::MAX,
                    max_bytes: 8 << 20,
                    max_chunks: 4096,
                },
                retention: RetentionPolicy::Ring,
                created_unix_secs: 7,
                recipient: "host:test".to_string(),
                wrapped_data_key_b64: "wrapped".to_string(),
            },
        )
    }

    /// Push `payloads` through a real writer while mirroring each landed
    /// chunk, the way the durable writer thread does.
    fn capture(dir: &Path, payloads: &[&[u8]]) -> TranscriptManifest {
        let mut writer = writer_at(dir);
        let mut journal = CaptureJournal::new(dir, writer.sealed_manifest());
        for payload in payloads {
            writer.push(Direction::Stdout, payload).expect("push");
            let chunk = writer.last_chunk().expect("a landed push has a record");
            journal.record(
                chunk,
                JournalShortfall {
                    refused_chunks: writer.refused_chunks(),
                    refused_bytes: writer.refused_bytes(),
                    evicted_chunks: writer.evicted_chunks(),
                    evicted_bytes: writer.evicted_bytes(),
                },
            );
        }
        writer.seal()
    }

    #[test]
    fn a_replayed_capture_matches_what_the_writer_would_have_sealed() {
        // The mirror has to reproduce the writer's own manifest, or the
        // cross-process seal describes a different capture than the one on
        // disk and verification refuses it.
        let dir = tempfile::tempdir().expect("tempdir");
        let sealed = capture(dir.path(), &[b"one", b"two", b"three"]);
        let replayed = replay(dir.path()).expect("a journalled capture replays");

        assert_eq!(replayed.manifest.chunks, sealed.chunks);
        assert_eq!(replayed.manifest.binding, sealed.binding);
        assert_eq!(
            replayed.manifest.wrapped_data_key_b64,
            sealed.wrapped_data_key_b64
        );
        verify_sealed_root(&replayed.manifest).expect("a replayed manifest verifies");
    }

    #[test]
    fn a_replayed_capture_never_claims_to_be_whole() {
        let dir = tempfile::tempdir().expect("tempdir");
        capture(dir.path(), &[b"one"]);
        let replayed = replay(dir.path()).expect("replay");
        assert!(replayed.manifest.adopted);
        assert!(
            replayed.manifest.is_truncated(),
            "a rebuilt seal cannot account for what its writer dropped on the way out"
        );
    }

    #[test]
    fn a_torn_final_line_costs_one_record_rather_than_the_capture() {
        // What a killed process leaves: the last append got partway out.
        let dir = tempfile::tempdir().expect("tempdir");
        capture(dir.path(), &[b"one", b"two", b"three"]);
        let path = dir.path().join(JOURNAL_FILENAME);
        let whole = std::fs::read(&path).expect("read journal");
        std::fs::write(&path, &whole[..whole.len() - 12]).expect("tear the journal");

        let replayed = replay(dir.path()).expect("a torn journal still replays");
        assert_eq!(replayed.manifest.chunks.len(), 2);
        verify_sealed_root(&replayed.manifest).expect("verify");
    }

    #[test]
    fn a_capture_with_no_journal_does_not_replay() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(replay(dir.path()), None);
    }

    #[test]
    fn a_journal_with_only_a_header_replays_an_empty_capture() {
        // A workload that booted and printed nothing before it was stopped.
        // The header is written with the first chunk, so this shape only
        // arises from a journal whose chunk lines were all torn off.
        let dir = tempfile::tempdir().expect("tempdir");
        capture(dir.path(), &[b"one"]);
        let path = dir.path().join(JOURNAL_FILENAME);
        let whole = std::fs::read_to_string(&path).expect("read journal");
        let header = whole.lines().next().expect("a header line");
        std::fs::write(&path, format!("{header}\n")).expect("keep only the header");

        let replayed = replay(dir.path()).expect("replay");
        assert!(replayed.manifest.chunks.is_empty());
        assert!(replayed.declared_lengths.is_empty());
        verify_sealed_root(&replayed.manifest).expect("verify");
    }

    #[test]
    fn declared_lengths_report_the_whole_of_each_segment_the_records_tile() {
        let dir = tempfile::tempdir().expect("tempdir");
        capture(dir.path(), &[b"one", b"two"]);
        let replayed = replay(dir.path()).expect("replay");
        assert_eq!(replayed.declared_lengths.len(), 1, "one segment");
        let (file, declared) = &replayed.declared_lengths[0];
        let actual = std::fs::metadata(dir.path().join(file))
            .expect("segment on disk")
            .len();
        assert_eq!(*declared, actual);
    }

    #[test]
    fn an_evicted_head_is_replayed_as_the_surviving_window() {
        // Ring retention unlinks whole segments. A replay that kept their
        // records would name files that are no longer there.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut writer = TranscriptWriter::new(
            dir.path(),
            mvm_core::crypto::aead::Key::from_bytes([0x22; 32]),
            TranscriptWriterConfig {
                capture_id: "capture-ring".to_string(),
                binding: CaptureBinding {
                    tenant_id: "local".to_string(),
                    vm_name: "vm-ring".to_string(),
                    session_id: None,
                },
                // Tight enough that the ring must unlink a sealed segment
                // once one has rolled — retention frees whole segments, so a
                // bound below a single segment would evict nothing.
                bounds: CaptureBounds {
                    max_duration_secs: u64::MAX,
                    max_bytes: 1 << 20,
                    max_chunks: u64::MAX,
                },
                retention: RetentionPolicy::Ring,
                created_unix_secs: 0,
                recipient: "host:test".to_string(),
                wrapped_data_key_b64: "wrapped".to_string(),
            },
        );
        let mut journal = CaptureJournal::new(dir.path(), writer.sealed_manifest());
        let payload = vec![b'x'; 4096];
        for _ in 0..600u32 {
            writer
                .push(Direction::Stdout, &payload)
                .expect("ring retention never refuses");
            let chunk = writer.last_chunk().expect("record");
            journal.record(
                chunk,
                JournalShortfall {
                    refused_chunks: writer.refused_chunks(),
                    refused_bytes: writer.refused_bytes(),
                    evicted_chunks: writer.evicted_chunks(),
                    evicted_bytes: writer.evicted_bytes(),
                },
            );
        }
        let sealed = writer.seal();
        assert!(sealed.evicted_chunks > 0, "the fixture must have evicted");

        let replayed = replay(dir.path()).expect("replay");
        assert_eq!(replayed.manifest.chunks, sealed.chunks);
        assert_eq!(replayed.manifest.evicted_chunks, sealed.evicted_chunks);
        verify_sealed_root(&replayed.manifest).expect("verify");
    }
}
