//! Forensic transcript capture — sealed manifest format, bounded-capture
//! budget, and tamper verification.
//!
//! This is the integrity + bounds core only: it defines the on-disk manifest
//! for sealed transcript chunks, a fail-closed capture budget, and a verifier
//! that re-hashes chunks against the manifest. The capture sink, at-rest
//! payload encryption, and the operator CLI build on these types — raw payloads
//! are never written to the normal audit chain, and capture is opt-in and
//! bounded.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::crypto::aead;

mod ring;
mod segment;
pub use ring::*;
pub use segment::{SEGMENT_MAX_CHUNKS, SEGMENT_MAX_CIPHERTEXT_BYTES, SegmentBounds};

/// Filename of the host transcript key-encryption key, under the keys dir.
pub const TRANSCRIPT_KEK_FILENAME: &str = "transcript-kek.bin";

/// Current sealed-transcript manifest format. Unknown versions fail closed.
///
/// Bumped 2 -> 3 when `ChunkRecord` grew `prev_hash`: that field is part of
/// every chunk leaf the sealed root commits to, so a manifest sealed under
/// the old layout now recomputes to a different root. Without the bump that
/// manifest would fail `verify_sealed_root` with `SealedRootMismatch` —
/// indistinguishable from actual tampering. Bumping the version makes
/// `validate_format` (which every verifier calls before touching the root)
/// reject it first, with an honest "old format" error instead of a false
/// tamper signal.
///
/// Bumped 3 -> 4 when the manifest grew `refused_chunks`/`refused_bytes`, for
/// the same reason: the sealed root now commits to them, so an old manifest
/// would recompute to a different root and look tampered.
///
/// Bumped 4 -> 5 when chunks moved from one file each into shared segments:
/// `ChunkRecord` grew `offset`, and the manifest grew `retention` plus
/// `evicted_chunks`/`evicted_bytes`. Same reason again — every one of those is
/// inside the sealed root.
pub const TRANSCRIPT_MANIFEST_FORMAT_VERSION: u32 = 5;

/// Direction of a captured chunk relative to the workload: network egress/
/// ingress, or one of the workload's own output streams (stdout/stderr) plus
/// a trace channel for structured diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Egress,
    Ingress,
    Stdout,
    Stderr,
    Trace,
}

/// One sealed transcript chunk recorded in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkRecord {
    pub seq: u64,
    /// Segment filename, relative to the manifest directory. No path
    /// components — verification rejects anything containing `/`, `\`, or `..`.
    /// One segment holds many chunks, so this is shared with the chunks
    /// written either side of this one.
    pub file: String,
    /// Byte offset of this chunk's ciphertext inside `file`. Records tile
    /// their segment exactly: verification refuses a gap, an overlap, or a
    /// trailing byte no record accounts for. `#[serde(default)]` so manifests
    /// written under the one-file-per-chunk layout still parse (and are then
    /// refused on their format version, not misread as offset 0).
    #[serde(default)]
    pub offset: u64,
    /// Sha256 (hex) of **this chunk's** ciphertext bytes — not the segment's.
    /// Batching moved where the bytes live; it did not coarsen what the sealed
    /// root commits to.
    pub sha256_hex: String,
    /// Ciphertext length of this chunk, i.e. the width of its slice of `file`.
    pub size_bytes: u64,
    pub direction: Direction,
    /// True when the frame was denied by egress policy (dropped, not forwarded)
    /// rather than crossing the boundary — forensically the interesting case (an
    /// attempt to reach a blocked endpoint). `#[serde(default)]` so manifests
    /// written before this field parse as `false` (forwarded).
    #[serde(default)]
    pub dropped: bool,
    /// Sha256 (hex) of the previous chunk's on-disk ciphertext; all-zero
    /// (64 `0` characters) for the first chunk. Chains chunks together so a
    /// reordered or spliced-in record no longer matches its neighbor once the
    /// sealed root is recomputed. `#[serde(default)]` so manifests written
    /// before this field still parse — an empty string can never collide with
    /// a real hash.
    #[serde(default)]
    pub prev_hash: String,
}

/// Which admitted workload/session a transcript belongs to. Capture is never
/// tenant-wide by default; it is armed for a specific binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBinding {
    pub tenant_id: String,
    pub vm_name: String,
    pub session_id: Option<String>,
}

/// Hard bounds on a capture. Exceeding any one fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureBounds {
    pub max_duration_secs: u64,
    pub max_bytes: u64,
    pub max_chunks: u64,
}

/// Sealed-transcript manifest, persisted alongside the encrypted chunk files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptManifest {
    pub format_version: u32,
    pub capture_id: String,
    pub binding: CaptureBinding,
    pub bounds: CaptureBounds,
    pub created_unix_secs: u64,
    /// Wrapped per-capture data key (base64). Empty until the capture seals
    /// under the at-rest-encryption slice; only `recipient` can unwrap it.
    pub wrapped_data_key_b64: String,
    /// Recipient binding allowed to decrypt later (e.g. a host key id).
    pub recipient: String,
    /// Which admission policy this capture ran under. Sealed in the root so a
    /// window whose head is gone cannot be passed off as a fail-closed
    /// capture that simply never received those chunks.
    #[serde(default)]
    pub retention: RetentionPolicy,
    pub chunks: Vec<ChunkRecord>,
    /// Chunks the writer was offered and did not store, because a bound was
    /// reached or the write failed. Nonzero means `chunks` is a **prefix** of
    /// what was captured, not the whole of it.
    ///
    /// Without this, a capture that stopped at its bound seals into a
    /// manifest that passes both [`verify_sealed_root`] and [`verify_chunks`]
    /// with nothing saying it is incomplete — a silently truncated artifact
    /// that looks trustworthy. The sealed root commits to it, so it cannot be
    /// stripped without breaking verification.
    #[serde(default)]
    pub refused_chunks: u64,
    /// Plaintext bytes in the chunks counted by `refused_chunks`.
    #[serde(default)]
    pub refused_bytes: u64,
    /// Chunks that landed and were later dropped by [`RetentionPolicy::Ring`]
    /// to make room for newer ones. Nonzero means `chunks` is a **suffix** of
    /// what was captured — the opposite end from `refused_chunks`, and the
    /// distinction a reader needs to know which way the record is incomplete.
    ///
    /// The surviving window starts at `chunks[0].seq`, and `chunks[0]`'s
    /// `prev_hash` still names the evicted chunk before it, so the linkage
    /// anchors the window rather than pretending it is genesis.
    #[serde(default)]
    pub evicted_chunks: u64,
    /// Plaintext bytes in the chunks counted by `evicted_chunks`.
    #[serde(default)]
    pub evicted_bytes: u64,
    /// RFC-6962 Merkle root over the capture binding, sealed-key metadata,
    /// bounds, retention policy, refusal and eviction counts, and ordered
    /// chunk records. The chunk records contain ciphertext digests, never
    /// plaintext digests.
    #[serde(default)]
    pub sealed_root_hex: String,
}

impl TranscriptManifest {
    /// Whether this transcript is missing chunks that were captured — lost
    /// off the tail at a bound, or evicted off the head by the ring. A
    /// consumer must not read either as a complete record of the workload's
    /// output.
    pub fn is_truncated(&self) -> bool {
        self.refused_chunks > 0 || self.evicted_chunks > 0
    }
}

/// Why a transcript operation refused. Fail-closed: any variant means the
/// caller must not treat the transcript as trustworthy/complete.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TranscriptError {
    #[error("capture bound exceeded: {0}")]
    BoundExceeded(String),
    #[error("unknown transcript manifest format version {got} (expected {expected})")]
    UnknownFormatVersion { got: u32, expected: u32 },
    #[error("chunk {seq} ({file}) missing on disk")]
    MissingChunk { seq: u64, file: String },
    #[error("chunk {seq} ({file}) hash mismatch (tampered)")]
    HashMismatch { seq: u64, file: String },
    #[error("unsafe chunk filename {0:?} (path components not allowed)")]
    UnsafeChunkName(String),
    #[error("segment {file} holds {actual} bytes but the manifest accounts for {declared}")]
    SegmentLengthMismatch {
        file: String,
        declared: u64,
        actual: u64,
    },
    #[error("chunk {seq} does not tile segment {file}: offset {offset}, expected {expected}")]
    SegmentLayoutInvalid {
        seq: u64,
        file: String,
        offset: u64,
        expected: u64,
    },
    #[error("segment {file} appears in more than one place in the manifest")]
    SegmentRepeated { file: String },
    #[error("io error verifying {file}: {msg}")]
    Io { file: String, msg: String },
    #[error("chunk {seq} ({file}) failed to decrypt (wrong key or tampered ciphertext)")]
    Decrypt { seq: u64, file: String },
    #[error("wrapped transcript key is malformed or cannot be unwrapped")]
    WrappedKeyInvalid,
    #[error("sealed transcript root is missing")]
    SealedRootMissing,
    #[error("sealed transcript root must be 64 lowercase hex characters")]
    SealedRootMalformed,
    #[error("sealed transcript root does not match the manifest")]
    SealedRootMismatch,
    #[error("sealed transcript root metadata could not be serialized: {0}")]
    SealedRootSerialization(String),
}

#[derive(Serialize)]
struct RootMetadata<'a> {
    domain: &'static str,
    format_version: u32,
    capture_id: &'a str,
    binding: &'a CaptureBinding,
    bounds: &'a CaptureBounds,
    created_unix_secs: u64,
    wrapped_data_key_b64: &'a str,
    recipient: &'a str,
    retention: RetentionPolicy,
    chunk_count: usize,
    refused_chunks: u64,
    refused_bytes: u64,
    evicted_chunks: u64,
    evicted_bytes: u64,
}

#[derive(Serialize)]
struct RootChunk<'a> {
    domain: &'static str,
    chunk: &'a ChunkRecord,
}

/// Recompute the manifest's content address. Leaves use fixed-field-order JSON
/// and the shared RFC-6962 tree implementation; the domain strings keep this
/// tree distinct from audit-log trees and distinguish metadata from chunks.
pub fn sealed_root_hex(manifest: &TranscriptManifest) -> Result<String, TranscriptError> {
    validate_format(manifest)?;
    let metadata = RootMetadata {
        domain: "mvm.transcript.metadata.v1",
        format_version: manifest.format_version,
        capture_id: &manifest.capture_id,
        binding: &manifest.binding,
        bounds: &manifest.bounds,
        created_unix_secs: manifest.created_unix_secs,
        wrapped_data_key_b64: &manifest.wrapped_data_key_b64,
        recipient: &manifest.recipient,
        retention: manifest.retention,
        chunk_count: manifest.chunks.len(),
        refused_chunks: manifest.refused_chunks,
        refused_bytes: manifest.refused_bytes,
        evicted_chunks: manifest.evicted_chunks,
        evicted_bytes: manifest.evicted_bytes,
    };
    let mut leaves = Vec::with_capacity(manifest.chunks.len() + 1);
    leaves.push(
        serde_json::to_vec(&metadata)
            .map_err(|e| TranscriptError::SealedRootSerialization(e.to_string()))?,
    );
    for chunk in &manifest.chunks {
        leaves.push(
            serde_json::to_vec(&RootChunk {
                domain: "mvm.transcript.chunk.v1",
                chunk,
            })
            .map_err(|e| TranscriptError::SealedRootSerialization(e.to_string()))?,
        );
    }
    Ok(hex::encode(mvm_protocol::merkle::merkle_root(&leaves)))
}

/// Verify the manifest-stored root against a fresh recomputation. This checks
/// manifest integrity; callers that need authenticated provenance must also
/// compare the recomputed root with the host-signed audit-chain label.
pub fn verify_sealed_root(manifest: &TranscriptManifest) -> Result<(), TranscriptError> {
    validate_format(manifest)?;
    if manifest.sealed_root_hex.is_empty() {
        return Err(TranscriptError::SealedRootMissing);
    }
    if manifest.sealed_root_hex.len() != 64
        || !manifest
            .sealed_root_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(TranscriptError::SealedRootMalformed);
    }
    if sealed_root_hex(manifest)? != manifest.sealed_root_hex {
        return Err(TranscriptError::SealedRootMismatch);
    }
    Ok(())
}

fn validate_format(manifest: &TranscriptManifest) -> Result<(), TranscriptError> {
    if manifest.format_version != TRANSCRIPT_MANIFEST_FORMAT_VERSION {
        return Err(TranscriptError::UnknownFormatVersion {
            got: manifest.format_version,
            expected: TRANSCRIPT_MANIFEST_FORMAT_VERSION,
        });
    }
    Ok(())
}

/// Accumulates a live capture and fails closed the moment a bound is hit.
pub struct CaptureBudget {
    bounds: CaptureBounds,
    bytes: u64,
    chunks: u64,
}

impl CaptureBudget {
    pub fn new(bounds: CaptureBounds) -> Self {
        Self {
            bounds,
            bytes: 0,
            chunks: 0,
        }
    }

    /// Admit one more chunk of `size` bytes, or fail closed. Checked before any
    /// payload is written, so an over-bound capture never lands bytes on disk.
    pub fn try_add(&mut self, size: u64) -> Result<(), TranscriptError> {
        if self.chunks + 1 > self.bounds.max_chunks {
            return Err(TranscriptError::BoundExceeded(format!(
                "max_chunks {} reached",
                self.bounds.max_chunks
            )));
        }
        let next = self.bytes.saturating_add(size);
        if next > self.bounds.max_bytes {
            return Err(TranscriptError::BoundExceeded(format!(
                "max_bytes {} would be exceeded ({} + {})",
                self.bounds.max_bytes, self.bytes, size
            )));
        }
        self.bytes = next;
        self.chunks += 1;
        Ok(())
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn chunks(&self) -> u64 {
        self.chunks
    }
}

/// Verify every manifest chunk against the segment holding it. Fails closed on
/// an unknown format version, an unsafe filename, a segment that is short
/// (torn), long (bytes nothing accounts for), missing, or whose records do not
/// tile it, and on any chunk whose own ciphertext digest no longer matches.
/// Integrity only — does not decrypt.
pub fn verify_chunks(manifest: &TranscriptManifest, dir: &Path) -> Result<(), TranscriptError> {
    validate_format(manifest)?;
    segment::verify_segments(&manifest.chunks, dir)
}

/// Bounded, AEAD-encrypting transcript writer. Each pushed payload is admitted
/// against this capture's [`RetentionPolicy`] *before* it is written, encrypted
/// at rest with the per-capture data key, appended to the current segment, and
/// recorded in the manifest by the sha256 of its own **ciphertext** (so
/// [`verify_chunks`] re-hashes exactly those bytes on disk). The raw data key
/// is the caller's to wrap for `recipient`; the writer only records the
/// already-wrapped form.
///
/// Many chunks share one segment file: the `segment` submodule holds the
/// layout, and the reason retention evicts whole segments rather than chunks.
pub struct TranscriptWriter {
    key: aead::Key,
    store: segment::SegmentStore,
    budget: CaptureBudget,
    retention: RetentionPolicy,
    /// Live records, oldest first. A deque because ring eviction drops from
    /// the front on every pruning admission.
    chunks: VecDeque<ChunkRecord>,
    /// Monotonic across evictions: a surviving window keeps the sequence
    /// numbers the capture actually issued, so a gap reads as a gap.
    next_seq: u64,
    /// Digest of the newest chunk written, held separately from `chunks`
    /// because eviction may have dropped the record carrying it while the
    /// linkage it anchors must stay intact.
    prev_hash: String,
    capture_id: String,
    binding: CaptureBinding,
    bounds: CaptureBounds,
    created_unix_secs: u64,
    wrapped_data_key_b64: String,
    recipient: String,
    refused_chunks: u64,
    refused_bytes: u64,
    evicted_chunks: u64,
    evicted_bytes: u64,
}

/// Construction parameters for a [`TranscriptWriter`] (grouped to keep the
/// constructor narrow). `wrapped_data_key_b64` is the per-capture key wrapped
/// for `recipient`; the writer records it verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptWriterConfig {
    pub capture_id: String,
    pub binding: CaptureBinding,
    pub bounds: CaptureBounds,
    /// What happens at a bound: refuse the newest chunk, or drop the oldest.
    /// A forensic capture of discrete frames wants the former; a continuous
    /// output stream, where going quiet is the failure, wants the latter.
    pub retention: RetentionPolicy,
    pub created_unix_secs: u64,
    pub recipient: String,
    pub wrapped_data_key_b64: String,
}

impl TranscriptWriter {
    /// `dir` must already exist. `key` encrypts chunks at rest.
    pub fn new(dir: impl Into<PathBuf>, key: aead::Key, config: TranscriptWriterConfig) -> Self {
        Self {
            key,
            store: segment::SegmentStore::new(dir.into(), SegmentBounds::default()),
            budget: CaptureBudget::new(config.bounds),
            retention: config.retention,
            chunks: VecDeque::new(),
            next_seq: 0,
            prev_hash: "0".repeat(64),
            capture_id: config.capture_id,
            binding: config.binding,
            bounds: config.bounds,
            created_unix_secs: config.created_unix_secs,
            wrapped_data_key_b64: config.wrapped_data_key_b64,
            recipient: config.recipient,
            refused_chunks: 0,
            refused_bytes: 0,
            evicted_chunks: 0,
            evicted_bytes: 0,
        }
    }

    /// Chunks offered to [`push`](Self::push)/[`push_dropped`](Self::push_dropped)
    /// that never landed. Nonzero means the capture lost its tail.
    pub fn refused_chunks(&self) -> u64 {
        self.refused_chunks
    }

    /// Plaintext bytes in the chunks counted by
    /// [`refused_chunks`](Self::refused_chunks).
    pub fn refused_bytes(&self) -> u64 {
        self.refused_bytes
    }

    /// Chunks that landed and were later dropped by ring retention. Nonzero
    /// means the capture lost its head.
    pub fn evicted_chunks(&self) -> u64 {
        self.evicted_chunks
    }

    /// Plaintext bytes in the chunks counted by
    /// [`evicted_chunks`](Self::evicted_chunks).
    pub fn evicted_bytes(&self) -> u64 {
        self.evicted_bytes
    }

    /// Segment files this capture currently owns. Bounded by retention, and —
    /// unlike the chunk count — no longer growing one per push.
    pub fn segment_count(&self) -> usize {
        self.store.segment_count()
    }

    /// Encrypt and append one payload chunk, or fail closed on a bound. The
    /// budget is checked on the *plaintext* size before any ciphertext lands.
    pub fn push(&mut self, direction: Direction, plaintext: &[u8]) -> Result<(), TranscriptError> {
        self.push_inner(direction, false, plaintext)
    }

    /// Append a frame that egress policy **denied** (dropped, not forwarded),
    /// recorded with `dropped = true`. Same bounds + at-rest encryption as
    /// [`push`]; lets the forensic transcript show attempted-but-blocked egress.
    pub fn push_dropped(
        &mut self,
        direction: Direction,
        plaintext: &[u8],
    ) -> Result<(), TranscriptError> {
        self.push_inner(direction, true, plaintext)
    }

    /// Write the chunk, and remember it if it did not land.
    ///
    /// Every refusal — a bound reached, a write that failed — is a hole in
    /// the capture. Counting it here, at the one place a chunk can fail to
    /// land, is what lets [`seal`](Self::seal) mark the manifest truncated
    /// instead of handing back an artifact that verifies clean while being
    /// silently incomplete.
    fn push_inner(
        &mut self,
        direction: Direction,
        dropped: bool,
        plaintext: &[u8],
    ) -> Result<(), TranscriptError> {
        let result = self.write_chunk(direction, dropped, plaintext);
        if result.is_err() {
            self.refused_chunks = self.refused_chunks.saturating_add(1);
            self.refused_bytes = self.refused_bytes.saturating_add(plaintext.len() as u64);
        }
        result
    }

    fn write_chunk(
        &mut self,
        direction: Direction,
        dropped: bool,
        plaintext: &[u8],
    ) -> Result<(), TranscriptError> {
        self.admit(plaintext.len() as u64)?;
        let ciphertext = aead::seal(&self.key, plaintext);
        let placement = self.store.append(&ciphertext, plaintext.len() as u64)?;
        let sha256_hex = crate::plan::bundle::sha256_hex(&ciphertext);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let prev_hash = std::mem::replace(&mut self.prev_hash, sha256_hex.clone());
        self.chunks.push_back(ChunkRecord {
            seq,
            file: placement.file,
            offset: placement.offset,
            sha256_hex,
            size_bytes: ciphertext.len() as u64,
            direction,
            dropped,
            prev_hash,
        });
        Ok(())
    }

    /// Make room for one more `size`-byte chunk, per this capture's policy.
    ///
    /// [`RetentionPolicy::FailClosed`] refuses once the budget is spent.
    /// [`RetentionPolicy::Ring`] never refuses: it frees whole sealed segments
    /// until the newest chunk fits, and admits it regardless when there is
    /// nothing left to free. That is the same "the newest write always wins"
    /// decision the reader queues make, applied to the persisted copy.
    fn admit(&mut self, size: u64) -> Result<(), TranscriptError> {
        match self.retention {
            RetentionPolicy::FailClosed => self.budget.try_add(size),
            RetentionPolicy::Ring => {
                self.evict_for(size);
                Ok(())
            }
        }
    }

    /// Unlink whole sealed segments until `size` fits, dropping the records
    /// they held.
    ///
    /// Eviction is oldest-first over an append-ordered store, so the records
    /// for the unlinked segments are exactly the front of the queue.
    fn evict_for(&mut self, size: u64) {
        let evicted = self.store.evict_for(size, self.bounds);
        if evicted.chunks == 0 {
            return;
        }
        self.evicted_chunks = self.evicted_chunks.saturating_add(evicted.chunks);
        self.evicted_bytes = self.evicted_bytes.saturating_add(evicted.bytes);
        for _ in 0..evicted.chunks {
            self.chunks.pop_front();
        }
    }

    /// Finalize the manifest for the chunks still held, carrying forward how
    /// many were refused off the tail and evicted off the head so the artifact
    /// declares its own completeness.
    pub fn seal(self) -> TranscriptManifest {
        let mut manifest = TranscriptManifest {
            format_version: TRANSCRIPT_MANIFEST_FORMAT_VERSION,
            capture_id: self.capture_id,
            binding: self.binding,
            bounds: self.bounds,
            created_unix_secs: self.created_unix_secs,
            wrapped_data_key_b64: self.wrapped_data_key_b64,
            recipient: self.recipient,
            retention: self.retention,
            chunks: self.chunks.into(),
            refused_chunks: self.refused_chunks,
            refused_bytes: self.refused_bytes,
            evicted_chunks: self.evicted_chunks,
            evicted_bytes: self.evicted_bytes,
            sealed_root_hex: String::new(),
        };
        manifest.sealed_root_hex =
            sealed_root_hex(&manifest).expect("fixed transcript root metadata serializes");
        manifest
    }
}

/// Verify a sealed transcript and decrypt its chunks back to the original
/// plaintext stream. Integrity is checked first ([`verify_chunks`]); a wrong
/// key or tampered ciphertext fails closed on decrypt.
pub fn export(
    manifest: &TranscriptManifest,
    dir: &Path,
    key: &aead::Key,
) -> Result<Vec<u8>, TranscriptError> {
    verify_sealed_root(manifest)?;
    verify_chunks(manifest, dir)?;
    // Verification proved every segment is exactly as long as its records
    // account for, so each read below is bounded by bytes already on disk and
    // each slice is in range.
    let mut out = Vec::new();
    for span in segment::segment_spans(&manifest.chunks)? {
        let bytes = std::fs::read(dir.join(span.file)).map_err(|e| TranscriptError::Io {
            file: span.file.to_string(),
            msg: e.to_string(),
        })?;
        for chunk in span.chunks {
            let ciphertext = segment::slice_chunk(&bytes, chunk)?;
            let plaintext = aead::open(key, ciphertext).map_err(|_| TranscriptError::Decrypt {
                seq: chunk.seq,
                file: chunk.file.clone(),
            })?;
            out.extend_from_slice(&plaintext);
        }
    }
    Ok(out)
}

/// Load the host transcript key-encryption key from `keys_dir`, creating it
/// (mode 0600) on first use. Every per-capture data key is wrapped under this
/// KEK so payloads stay unreadable without host access.
pub fn load_or_init_kek(keys_dir: &Path) -> std::io::Result<aead::Key> {
    let path = keys_dir.join(TRANSCRIPT_KEK_FILENAME);
    if path.exists() {
        return aead::Key::load(&path);
    }
    std::fs::create_dir_all(keys_dir)?;
    let kek = aead::Key::random();
    kek.persist(&path, 0o600)?;
    Ok(kek)
}

/// Wrap a per-capture data key under the host KEK, base64 for the manifest's
/// `wrapped_data_key_b64`.
pub fn wrap_data_key(kek: &aead::Key, data_key: &aead::Key) -> String {
    B64.encode(data_key.wrap_under(kek))
}

/// Recover a per-capture data key from the manifest's `wrapped_data_key_b64`.
/// Fails closed on bad base64, a wrong KEK, or a tampered wrap.
pub fn unwrap_data_key(kek: &aead::Key, wrapped_b64: &str) -> Result<aead::Key, TranscriptError> {
    let framed = B64
        .decode(wrapped_b64)
        .map_err(|_| TranscriptError::WrappedKeyInvalid)?;
    aead::Key::unwrap_under(kek, &framed).map_err(|_| TranscriptError::WrappedKeyInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> CaptureBounds {
        CaptureBounds {
            max_duration_secs: 60,
            max_bytes: 1000,
            max_chunks: 3,
        }
    }

    fn manifest(chunks: Vec<ChunkRecord>) -> TranscriptManifest {
        let mut manifest = TranscriptManifest {
            format_version: TRANSCRIPT_MANIFEST_FORMAT_VERSION,
            capture_id: "cap-1".to_string(),
            binding: CaptureBinding {
                tenant_id: "t".to_string(),
                vm_name: "vm".to_string(),
                session_id: None,
            },
            bounds: bounds(),
            created_unix_secs: 1,
            wrapped_data_key_b64: String::new(),
            recipient: "host-key-1".to_string(),
            retention: RetentionPolicy::FailClosed,
            chunks,
            refused_chunks: 0,
            refused_bytes: 0,
            evicted_chunks: 0,
            evicted_bytes: 0,
            sealed_root_hex: String::new(),
        };
        manifest.sealed_root_hex = sealed_root_hex(&manifest).unwrap();
        manifest
    }

    fn write_chunk(dir: &Path, name: &str, body: &[u8]) -> ChunkRecord {
        std::fs::write(dir.join(name), body).unwrap();
        let sha = crate::crypto::image_verify::sha256_file(&dir.join(name)).unwrap();
        ChunkRecord {
            seq: 0,
            file: name.to_string(),
            offset: 0,
            sha256_hex: sha,
            size_bytes: body.len() as u64,
            direction: Direction::Egress,
            dropped: false,
            prev_hash: "0".repeat(64),
        }
    }

    #[test]
    fn manifest_serde_roundtrips() {
        let m = manifest(vec![ChunkRecord {
            seq: 0,
            file: "0.bin".to_string(),
            offset: 0,
            sha256_hex: "ab".to_string(),
            size_bytes: 2,
            direction: Direction::Ingress,
            dropped: false,
            prev_hash: "0".repeat(64),
        }]);
        let json = serde_json::to_string(&m).unwrap();
        let back: TranscriptManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn stream_directions_round_trip_through_serde() {
        for d in [Direction::Stdout, Direction::Stderr, Direction::Trace] {
            let s = serde_json::to_string(&d).expect("serialize direction");
            let back: Direction = serde_json::from_str(&s).expect("deserialize direction");
            assert_eq!(d, back);
        }
    }

    #[test]
    fn chunk_missing_prev_hash_field_parses_with_empty_default() {
        // A manifest written before `prev_hash` existed has no such key; it
        // must still load rather than fail closed on an old capture.
        let json = r#"{"seq":0,"file":"0.chunk","sha256_hex":"ab","size_bytes":2,"direction":"egress","dropped":false}"#;
        let c: ChunkRecord = serde_json::from_str(json).expect("legacy chunk record parses");
        assert_eq!(c.prev_hash, "");
    }

    /// Shared by `sealed_root_vector_is_pinned` and
    /// `the_pre_linkage_root_vector_no_longer_verifies` so both tests exercise
    /// the exact same chunk records — the only thing that may differ between
    /// them is which root is stamped on the result.
    fn two_chunk_manifest() -> TranscriptManifest {
        manifest(vec![
            ChunkRecord {
                seq: 0,
                file: "0.seg".to_string(),
                offset: 0,
                sha256_hex: "11".repeat(32),
                size_bytes: 48,
                direction: Direction::Egress,
                dropped: false,
                prev_hash: "0".repeat(64),
            },
            ChunkRecord {
                seq: 1,
                file: "0.seg".to_string(),
                offset: 48,
                sha256_hex: "22".repeat(32),
                size_bytes: 64,
                direction: Direction::Ingress,
                dropped: true,
                prev_hash: "11".repeat(32),
            },
        ])
    }

    #[test]
    fn sealed_root_vector_is_pinned() {
        let m = two_chunk_manifest();
        assert_eq!(
            m.sealed_root_hex,
            "854edc1c7c06e0bed82ea0061653410cd33ab0d0e685f4e9ef8b9d9d911de320"
        );
    }

    /// The root `sealed_root_vector_is_pinned` pinned before the manifest
    /// grew `refused_chunks`/`refused_bytes`.
    const PRE_REFUSAL_ROOT_HEX: &str =
        "73b077cace4f804b2d2d83d293d12a0d63a398423bad12c611eb633b15c90206";

    #[test]
    fn a_manifest_sealed_before_the_refusal_count_fails_on_version_not_root() {
        // The whole reason the format version moved with the field: an honest
        // old capture must be refused as old, never as tampered.
        let mut m = manifest_with_root(PRE_REFUSAL_ROOT_HEX);
        m.format_version = 3;
        assert_eq!(
            verify_sealed_root(&m),
            Err(TranscriptError::UnknownFormatVersion {
                got: 3,
                expected: TRANSCRIPT_MANIFEST_FORMAT_VERSION
            })
        );
    }

    /// The root `sealed_root_vector_is_pinned` pinned before `ChunkRecord`
    /// grew `prev_hash`. Captured here, unchanged, only so the test below can
    /// prove it no longer verifies.
    const PRE_LINKAGE_ROOT_HEX: &str =
        "81cf47b6993c2752d0a50ed0051151d6354986863f5b6265ae723e664c4f6dda";

    /// The root `sealed_root_vector_is_pinned` pinned before chunks moved into
    /// shared segments — before `ChunkRecord` carried an `offset` and before
    /// the manifest carried a retention policy or an eviction count.
    const PRE_SEGMENT_ROOT_HEX: &str =
        "1c0d5a649e45081b0f2ac16d30744b97aff3117002717719e9ba1601d9ca1c29";

    /// Same chunk records as `two_chunk_manifest`, but stamped with a caller
    /// supplied root instead of a freshly computed one.
    fn manifest_with_root(root_hex: &str) -> TranscriptManifest {
        let mut m = two_chunk_manifest();
        m.sealed_root_hex = root_hex.to_string();
        m
    }

    #[test]
    fn the_pre_linkage_root_vector_no_longer_verifies() {
        // Guards the re-pin itself: if this ever passes again, the chunk-record
        // layout silently reverted and the new vector is meaningless.
        //
        // `two_chunk_manifest` stamps the *current* format_version (via the
        // `manifest` helper), so this exercises the root comparison, not the
        // version check: the manifest passes `validate_format` and only then
        // fails on the stale root.
        let m = manifest_with_root(PRE_LINKAGE_ROOT_HEX);
        assert_eq!(m.format_version, TRANSCRIPT_MANIFEST_FORMAT_VERSION);
        assert_eq!(
            verify_sealed_root(&m),
            Err(TranscriptError::SealedRootMismatch)
        );
    }

    #[test]
    fn a_manifest_sealed_before_segments_fails_on_version_not_root() {
        // Same reason as every prior re-pin: an honest capture written under
        // the one-file-per-chunk layout must be refused as old, never as
        // tampered. Confusing the two degrades the tamper signal itself.
        let mut m = manifest_with_root(PRE_SEGMENT_ROOT_HEX);
        m.format_version = 4;
        assert_eq!(
            verify_sealed_root(&m),
            Err(TranscriptError::UnknownFormatVersion {
                got: 4,
                expected: TRANSCRIPT_MANIFEST_FORMAT_VERSION
            })
        );
    }

    #[test]
    fn the_pre_segment_root_vector_no_longer_verifies() {
        // Guards the re-pin: if this ever passes again, the segment layout
        // silently reverted and the new vector means nothing.
        let m = manifest_with_root(PRE_SEGMENT_ROOT_HEX);
        assert_eq!(m.format_version, TRANSCRIPT_MANIFEST_FORMAT_VERSION);
        assert_eq!(
            verify_sealed_root(&m),
            Err(TranscriptError::SealedRootMismatch)
        );
    }

    #[test]
    fn stale_format_version_manifest_fails_on_version_not_root_mismatch() {
        // A manifest sealed by pre-linkage code: format_version 2, and a
        // chunk with no `prev_hash` key at all — not a defaulted empty
        // string, the key is simply absent, exactly like a real capture
        // written before the field existed. `sealed_root_hex` is some value
        // that pre-linkage code could plausibly have produced; its exact
        // content never matters, since the version check must refuse the
        // manifest before the root is ever compared.
        let json = format!(
            r#"{{"format_version":2,"capture_id":"cap-1","binding":{{"tenant_id":"t","vm_name":"vm","session_id":null}},"bounds":{{"max_duration_secs":60,"max_bytes":1000,"max_chunks":3}},"created_unix_secs":1,"wrapped_data_key_b64":"","recipient":"host-key-1","chunks":[{{"seq":0,"file":"0.chunk","sha256_hex":"{}","size_bytes":48,"direction":"egress","dropped":false}}],"sealed_root_hex":"{}"}}"#,
            "11".repeat(32),
            "33".repeat(32),
        );
        let m: TranscriptManifest =
            serde_json::from_str(&json).expect("a pre-linkage manifest still parses");
        assert_eq!(
            m.chunks[0].prev_hash, "",
            "no prev_hash key in the source JSON"
        );
        // An old-but-honest manifest and an attacker-tampered one must never
        // produce the same error: this is the version-refusal error, never
        // `SealedRootMismatch`.
        assert_eq!(
            verify_sealed_root(&m),
            Err(TranscriptError::UnknownFormatVersion {
                got: 2,
                expected: 5
            })
        );
    }

    #[test]
    fn current_format_version_manifest_round_trips_through_verify_and_export() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(4), writer_config());
        w.push(Direction::Stdout, b"hello ").unwrap();
        w.push(Direction::Stderr, b"world").unwrap();
        let manifest = w.seal();
        assert_eq!(manifest.format_version, TRANSCRIPT_MANIFEST_FORMAT_VERSION);
        verify_sealed_root(&manifest).expect("current-version manifest verifies");
        assert_eq!(
            export(&manifest, dir.path(), &fixed_key(4)).unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn manifest_rejects_unknown_fields() {
        let json = r#"{"format_version":1,"capture_id":"x","binding":{"tenant_id":"t","vm_name":"v","session_id":null},"bounds":{"max_duration_secs":1,"max_bytes":1,"max_chunks":1},"created_unix_secs":1,"wrapped_data_key_b64":"","recipient":"r","chunks":[],"surprise":true}"#;
        assert!(serde_json::from_str::<TranscriptManifest>(json).is_err());
    }

    #[test]
    fn budget_admits_within_bounds_then_fails_closed_on_bytes() {
        let mut b = CaptureBudget::new(bounds());
        b.try_add(600).unwrap();
        let err = b.try_add(500).unwrap_err(); // 600 + 500 > 1000
        assert!(matches!(err, TranscriptError::BoundExceeded(_)));
        assert_eq!(b.bytes(), 600, "the rejected chunk's bytes are not counted");
        assert_eq!(b.chunks(), 1);
    }

    #[test]
    fn budget_fails_closed_on_chunk_count() {
        let mut b = CaptureBudget::new(CaptureBounds {
            max_duration_secs: 60,
            max_bytes: u64::MAX,
            max_chunks: 2,
        });
        b.try_add(1).unwrap();
        b.try_add(1).unwrap();
        assert!(matches!(
            b.try_add(1).unwrap_err(),
            TranscriptError::BoundExceeded(_)
        ));
    }

    #[test]
    fn verify_passes_for_intact_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let c = write_chunk(dir.path(), "0.bin", b"hello world");
        assert!(verify_chunks(&manifest(vec![c]), dir.path()).is_ok());
    }

    #[test]
    fn verify_rejects_a_tampered_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let c = write_chunk(dir.path(), "0.bin", b"hello world");
        // Tamper after recording the manifest hash.
        std::fs::write(dir.path().join("0.bin"), b"hello WORLD").unwrap();
        let err = verify_chunks(&manifest(vec![c]), dir.path()).unwrap_err();
        assert!(matches!(err, TranscriptError::HashMismatch { .. }));
    }

    #[test]
    fn verify_rejects_a_missing_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let c = ChunkRecord {
            seq: 7,
            file: "gone.bin".to_string(),
            offset: 0,
            sha256_hex: "00".to_string(),
            size_bytes: 1,
            direction: Direction::Egress,
            dropped: false,
            prev_hash: "0".repeat(64),
        };
        assert!(matches!(
            verify_chunks(&manifest(vec![c]), dir.path()).unwrap_err(),
            TranscriptError::MissingChunk { seq: 7, .. }
        ));
    }

    #[test]
    fn verify_rejects_an_unsafe_chunk_name() {
        let dir = tempfile::tempdir().unwrap();
        let c = ChunkRecord {
            seq: 0,
            file: "../escape".to_string(),
            offset: 0,
            sha256_hex: "00".to_string(),
            size_bytes: 1,
            direction: Direction::Egress,
            dropped: false,
            prev_hash: "0".repeat(64),
        };
        assert!(matches!(
            verify_chunks(&manifest(vec![c]), dir.path()).unwrap_err(),
            TranscriptError::UnsafeChunkName(_)
        ));
    }

    #[test]
    fn verify_rejects_unknown_format_version() {
        let dir = tempfile::tempdir().unwrap();
        let mut m = manifest(vec![]);
        m.format_version = 999;
        assert!(matches!(
            verify_chunks(&m, dir.path()).unwrap_err(),
            TranscriptError::UnknownFormatVersion { got: 999, .. }
        ));
    }

    fn writer_config() -> TranscriptWriterConfig {
        TranscriptWriterConfig {
            capture_id: "cap-1".to_string(),
            binding: CaptureBinding {
                tenant_id: "t".to_string(),
                vm_name: "vm".to_string(),
                session_id: None,
            },
            bounds: bounds(),
            retention: RetentionPolicy::FailClosed,
            created_unix_secs: 1,
            recipient: "host-key-1".to_string(),
            wrapped_data_key_b64: "wrapped".to_string(),
        }
    }

    /// A writer with room for a real stream capture — wider bounds than
    /// [`bounds`], which is deliberately tight for budget-exhaustion tests.
    fn writer_at(dir: &Path) -> TranscriptWriter {
        let mut cfg = writer_config();
        cfg.bounds = CaptureBounds {
            max_duration_secs: 60,
            max_bytes: 1 << 20,
            max_chunks: 64,
        };
        TranscriptWriter::new(dir, fixed_key(1), cfg)
    }

    #[test]
    fn pushed_chunks_link_to_their_predecessor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut w = writer_at(dir.path());
        w.push(Direction::Stdout, b"one").expect("push one");
        w.push(Direction::Stdout, b"two").expect("push two");
        let m = w.seal();
        assert_eq!(m.chunks[0].prev_hash, "0".repeat(64));
        assert_eq!(m.chunks[1].prev_hash, m.chunks[0].sha256_hex);
    }

    #[test]
    fn sealed_root_binds_capture_metadata_and_ordered_ciphertext_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let key = aead::Key::from_bytes([6u8; 32]);
        let mut writer = TranscriptWriter::new(dir.path(), key, writer_config());
        writer.push(Direction::Egress, b"request").unwrap();
        writer
            .push_dropped(Direction::Ingress, b"response")
            .unwrap();
        let manifest = writer.seal();

        assert_eq!(manifest.sealed_root_hex.len(), 64);
        assert_eq!(
            sealed_root_hex(&manifest).unwrap(),
            manifest.sealed_root_hex
        );
        verify_sealed_root(&manifest).expect("freshly sealed manifest root verifies");

        let mut changed_binding = manifest.clone();
        changed_binding.binding.vm_name = "different-vm".into();
        assert!(matches!(
            verify_sealed_root(&changed_binding),
            Err(TranscriptError::SealedRootMismatch)
        ));

        let mut reordered = manifest.clone();
        reordered.chunks.reverse();
        assert!(matches!(
            verify_sealed_root(&reordered),
            Err(TranscriptError::SealedRootMismatch)
        ));

        let mut changed_digest = manifest.clone();
        changed_digest.chunks[0].sha256_hex = "00".repeat(32);
        assert!(matches!(
            verify_sealed_root(&changed_digest),
            Err(TranscriptError::SealedRootMismatch)
        ));
    }

    #[test]
    fn sealed_root_verification_rejects_an_absent_or_malformed_root() {
        let mut legacy = manifest(Vec::new());
        legacy.format_version = 1;
        legacy.sealed_root_hex.clear();
        assert!(matches!(
            verify_sealed_root(&legacy),
            Err(TranscriptError::UnknownFormatVersion { got: 1, .. })
        ));

        let mut manifest = manifest(Vec::new());
        manifest.sealed_root_hex.clear();
        assert!(matches!(
            verify_sealed_root(&manifest),
            Err(TranscriptError::SealedRootMissing)
        ));

        manifest.sealed_root_hex = "not-a-sha256".into();
        assert!(matches!(
            verify_sealed_root(&manifest),
            Err(TranscriptError::SealedRootMalformed)
        ));
    }

    // `aead::Key` is deliberately not `Clone`; build identical keys from bytes
    // so a test can both encrypt and later decrypt.
    fn fixed_key(b: u8) -> aead::Key {
        aead::Key::from_bytes([b; 32])
    }

    #[test]
    fn capture_then_export_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(7), writer_config());
        w.push(Direction::Egress, b"GET / HTTP/1.1\r\n").unwrap();
        w.push(Direction::Ingress, b"HTTP/1.1 200 OK\r\n").unwrap();
        let manifest = w.seal();
        assert_eq!(manifest.chunks.len(), 2);
        // Ciphertext on disk verifies, and decrypts back to the concatenation.
        verify_chunks(&manifest, dir.path()).unwrap();
        let out = export(&manifest, dir.path(), &fixed_key(7)).unwrap();
        assert_eq!(out, b"GET / HTTP/1.1\r\nHTTP/1.1 200 OK\r\n");
    }

    #[test]
    fn push_dropped_marks_the_chunk_and_still_exports() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(7), writer_config());
        w.push(Direction::Egress, b"allowed").unwrap();
        w.push_dropped(Direction::Egress, b"denied").unwrap();
        let manifest = w.seal();
        assert_eq!(manifest.chunks.len(), 2);
        assert!(!manifest.chunks[0].dropped, "forwarded frame not flagged");
        assert!(manifest.chunks[1].dropped, "denied frame flagged dropped");
        // Both are encrypted + verifiable + decrypt back in order.
        verify_chunks(&manifest, dir.path()).unwrap();
        assert_eq!(
            export(&manifest, dir.path(), &fixed_key(7)).unwrap(),
            b"alloweddenied"
        );
    }

    #[test]
    fn a_complete_capture_declares_itself_complete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut w = writer_at(dir.path());
        w.push(Direction::Stdout, b"all of it").expect("push");
        let manifest = w.seal();
        assert!(!manifest.is_truncated());
        assert_eq!(manifest.refused_chunks, 0);
        assert_eq!(manifest.refused_bytes, 0);
    }

    #[test]
    fn a_capture_that_hit_its_bound_seals_as_truncated() {
        // The forensic failure this exists for: without the refusal count a
        // capture that stopped at its bound verifies clean and reads as the
        // whole of a quiet workload's output.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = writer_config();
        cfg.bounds = CaptureBounds {
            max_duration_secs: 60,
            max_bytes: 1 << 20,
            max_chunks: 1,
        };
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(3), cfg);
        w.push(Direction::Stdout, b"first").expect("first fits");
        assert!(w.push(Direction::Stdout, b"second").is_err());
        assert!(w.push_dropped(Direction::Stderr, b"third!").is_err());
        assert_eq!(w.refused_chunks(), 2);
        assert_eq!(w.refused_bytes(), 12);

        let manifest = w.seal();
        assert_eq!(manifest.chunks.len(), 1);
        assert!(
            manifest.is_truncated(),
            "a manifest missing chunks must say so"
        );
        assert_eq!(manifest.refused_chunks, 2);
        assert_eq!(manifest.refused_bytes, 12);
        verify_sealed_root(&manifest).expect("a truncated capture still seals a valid root");
        verify_chunks(&manifest, dir.path()).expect("the chunks that did land verify");
    }

    #[test]
    fn hiding_the_refusal_count_breaks_the_sealed_root() {
        // The count is only worth anything if it cannot be filed off: the root
        // commits to it, so a truncated capture cannot be passed off as whole.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = writer_config();
        cfg.bounds = CaptureBounds {
            max_duration_secs: 60,
            max_bytes: 1 << 20,
            max_chunks: 1,
        };
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(3), cfg);
        w.push(Direction::Stdout, b"first").expect("first fits");
        assert!(w.push(Direction::Stdout, b"second").is_err());
        let mut manifest = w.seal();

        manifest.refused_chunks = 0;
        manifest.refused_bytes = 0;
        assert_eq!(
            verify_sealed_root(&manifest),
            Err(TranscriptError::SealedRootMismatch)
        );
    }

    #[test]
    fn export_fails_closed_on_a_tampered_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(7), writer_config());
        w.push(Direction::Egress, b"secret").unwrap();
        let manifest = w.seal();
        // Flip a byte in place (same length) so the hash check — not the size
        // check — is what refuses.
        let mut ct = std::fs::read(dir.path().join("0.seg")).unwrap();
        ct[0] ^= 0xff;
        std::fs::write(dir.path().join("0.seg"), &ct).unwrap();
        let err = export(&manifest, dir.path(), &fixed_key(7)).unwrap_err();
        assert!(matches!(err, TranscriptError::HashMismatch { .. }));
    }

    #[test]
    fn export_fails_closed_on_the_wrong_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(7), writer_config());
        w.push(Direction::Egress, b"secret").unwrap();
        let manifest = w.seal();
        // Integrity passes (ciphertext untouched) but the wrong key can't decrypt.
        assert!(matches!(
            export(&manifest, dir.path(), &fixed_key(9)).unwrap_err(),
            TranscriptError::Decrypt { .. }
        ));
    }

    #[test]
    fn kek_is_created_once_then_reused() {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        let k1 = load_or_init_kek(&keys).unwrap();
        let path = keys.join(TRANSCRIPT_KEK_FILENAME);
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "KEK file must be private");
        }
        // Reload returns a KEK that round-trips the same wrapped data key.
        let k2 = load_or_init_kek(&keys).unwrap();
        let data = aead::Key::from_bytes([5u8; 32]);
        let wrapped = wrap_data_key(&k1, &data);
        assert!(
            unwrap_data_key(&k2, &wrapped).is_ok(),
            "persisted KEK reused"
        );
    }

    #[test]
    fn wrap_unwrap_data_key_round_trips_and_rejects_garbage() {
        let kek = aead::Key::from_bytes([1u8; 32]);
        let data = aead::Key::from_bytes([2u8; 32]);
        let wrapped = wrap_data_key(&kek, &data);
        // Recovered key decrypts what the original sealed.
        let recovered = unwrap_data_key(&kek, &wrapped).unwrap();
        let blob = aead::seal(&data, b"payload");
        assert_eq!(aead::open(&recovered, &blob).unwrap(), b"payload");
        // Wrong KEK + non-base64 both fail closed.
        let wrong = aead::Key::from_bytes([3u8; 32]);
        assert!(matches!(
            unwrap_data_key(&wrong, &wrapped),
            Err(TranscriptError::WrappedKeyInvalid)
        ));
        assert!(matches!(
            unwrap_data_key(&kek, "not base64!!"),
            Err(TranscriptError::WrappedKeyInvalid)
        ));
    }

    #[test]
    fn wrapped_key_capture_and_export_round_trips_end_to_end() {
        // The full at-rest path: KEK wraps the data key in the manifest, the
        // capture encrypts under the data key, and export unwraps then decrypts.
        let dir = tempfile::tempdir().unwrap();
        let kek = load_or_init_kek(&dir.path().join("keys")).unwrap();
        let data = aead::Key::from_bytes([8u8; 32]);
        let mut cfg = writer_config();
        cfg.wrapped_data_key_b64 = wrap_data_key(&kek, &data);
        let mut w = TranscriptWriter::new(dir.path(), aead::Key::from_bytes([8u8; 32]), cfg);
        w.push(Direction::Egress, b"forensic payload").unwrap();
        let manifest = w.seal();
        // Operator-side: unwrap the data key from the manifest using the KEK,
        // then export.
        let recovered = unwrap_data_key(&kek, &manifest.wrapped_data_key_b64).unwrap();
        assert_eq!(
            export(&manifest, dir.path(), &recovered).unwrap(),
            b"forensic payload"
        );
    }

    #[test]
    fn push_fails_closed_on_budget_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let key = aead::Key::random();
        let mut cfg = writer_config();
        cfg.bounds = CaptureBounds {
            max_duration_secs: 60,
            max_bytes: 4,
            max_chunks: 10,
        };
        let mut w = TranscriptWriter::new(dir.path(), key, cfg);
        assert!(matches!(
            w.push(Direction::Egress, b"too-long").unwrap_err(),
            TranscriptError::BoundExceeded(_)
        ));
        assert!(
            !dir.path().join("0.seg").exists(),
            "no ciphertext lands when the budget refuses the chunk"
        );
    }

    // --- batching: many chunks, few files -------------------------------

    /// A writer wide enough that neither bound binds, so a test measures the
    /// segment layout rather than retention.
    fn roomy_writer_at(dir: &Path, retention: RetentionPolicy) -> TranscriptWriter {
        let mut cfg = writer_config();
        cfg.bounds = CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes: u64::MAX,
            max_chunks: u64::MAX,
        };
        cfg.retention = retention;
        TranscriptWriter::new(dir, fixed_key(11), cfg)
    }

    fn files_in(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .expect("read capture dir")
            .filter_map(Result::ok)
            .count()
    }

    #[test]
    fn a_hundred_thousand_chunks_produce_a_bounded_number_of_files() {
        // The regression this task exists for: one file per chunk made the
        // chunk cap an inode cap, and the cap had to be set below a second of
        // log output. Files must scale with bytes, not with pushes.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut w = roomy_writer_at(dir.path(), RetentionPolicy::FailClosed);
        for _ in 0..100_000 {
            w.push(Direction::Stdout, b"x").expect("push");
        }
        let segments = w.segment_count();
        let manifest = w.seal();
        assert_eq!(
            manifest.chunks.len(),
            100_000,
            "every chunk is still its own record"
        );

        // 1024 chunks per segment, and 100k one-byte chunks are far short of
        // the 1 MiB size trigger, so this is the count trigger alone.
        let ceiling = 100_000usize.div_ceil(SEGMENT_MAX_CHUNKS as usize) + 1;
        assert!(
            segments <= ceiling,
            "100k chunks landed in {segments} segments, expected at most {ceiling}"
        );
        assert_eq!(files_in(dir.path()), segments);
    }

    #[test]
    fn a_sealed_manifest_over_batched_segments_verifies_and_exports_in_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut w = roomy_writer_at(dir.path(), RetentionPolicy::FailClosed);
        // Enough pushes to cross several segment boundaries.
        let mut expected = Vec::new();
        for i in 0..(SEGMENT_MAX_CHUNKS * 3 + 7) {
            let body = format!("line-{i}\n").into_bytes();
            expected.extend_from_slice(&body);
            w.push(Direction::Stdout, &body).expect("push");
        }
        assert!(w.segment_count() >= 4, "the stream spans several segments");
        let manifest = w.seal();

        verify_sealed_root(&manifest).expect("a batched capture still seals a verifiable root");
        verify_chunks(&manifest, dir.path()).expect("every chunk verifies inside its segment");
        assert_eq!(
            export(&manifest, dir.path(), &fixed_key(11)).expect("export"),
            expected,
            "export reproduces the byte stream in order across segment boundaries"
        );
    }

    #[test]
    fn the_sealed_root_still_commits_to_each_chunks_own_digest() {
        // Batching moved the bytes, not what the root attests: changing one
        // chunk's recorded digest, while every other record and the segment
        // file stay untouched, must still break the root.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut w = roomy_writer_at(dir.path(), RetentionPolicy::FailClosed);
        for i in 0..8u8 {
            w.push(Direction::Stdout, &[i; 4]).expect("push");
        }
        let manifest = w.seal();
        assert_eq!(
            manifest
                .chunks
                .iter()
                .map(|c| c.file.as_str())
                .collect::<Vec<_>>(),
            vec!["0.seg"; 8],
            "all eight share one segment"
        );
        assert_ne!(
            manifest.chunks[3].sha256_hex, manifest.chunks[4].sha256_hex,
            "neighbours in one file still carry their own digests"
        );

        let mut filed_off = manifest.clone();
        filed_off.chunks[4].sha256_hex = "00".repeat(32);
        assert_eq!(
            verify_sealed_root(&filed_off),
            Err(TranscriptError::SealedRootMismatch)
        );

        let mut moved = manifest.clone();
        moved.chunks[4].offset += 1;
        assert_eq!(
            verify_sealed_root(&moved),
            Err(TranscriptError::SealedRootMismatch),
            "where a chunk sits in its segment is sealed too"
        );
    }

    #[test]
    fn one_tampered_byte_inside_a_segment_is_still_detected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut w = roomy_writer_at(dir.path(), RetentionPolicy::FailClosed);
        for i in 0..5u8 {
            w.push(Direction::Stdout, &[i; 16]).expect("push");
        }
        let manifest = w.seal();
        let target = &manifest.chunks[3];
        let path = dir.path().join(&target.file);
        let mut bytes = std::fs::read(&path).expect("segment");
        // Same length, inside the fourth chunk's range: the hash check, not
        // the length check, is what must refuse.
        let at = target.offset as usize + 2;
        bytes[at] ^= 0xff;
        std::fs::write(&path, &bytes).expect("tamper");

        assert_eq!(
            verify_chunks(&manifest, dir.path()),
            Err(TranscriptError::HashMismatch {
                seq: 3,
                file: target.file.clone(),
            })
        );
        assert!(export(&manifest, dir.path(), &fixed_key(11)).is_err());
    }

    #[test]
    fn a_torn_final_segment_fails_closed_rather_than_exporting_less() {
        // A capture killed mid-append leaves a short last segment. Exporting
        // the bytes that survived would hand back a silently shorter stream
        // that verifies clean.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut w = roomy_writer_at(dir.path(), RetentionPolicy::FailClosed);
        for i in 0..4u8 {
            w.push(Direction::Stdout, &[i; 8]).expect("push");
        }
        let manifest = w.seal();
        let path = dir.path().join(&manifest.chunks[0].file);
        let bytes = std::fs::read(&path).expect("segment");
        std::fs::write(&path, &bytes[..bytes.len() - 3]).expect("tear the tail off");

        let err = verify_chunks(&manifest, dir.path()).expect_err("a torn segment is refused");
        assert!(
            matches!(err, TranscriptError::SegmentLengthMismatch { .. }),
            "a torn capture must read as short, not as tampered: {err}"
        );
        assert!(export(&manifest, dir.path(), &fixed_key(11)).is_err());
    }

    // --- ring retention on the durable copy -----------------------------

    #[test]
    fn a_ring_capture_keeps_the_newest_window_instead_of_refusing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = writer_config();
        cfg.retention = RetentionPolicy::Ring;
        cfg.bounds = CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes: u64::MAX,
            max_chunks: 2 * SEGMENT_MAX_CHUNKS,
        };
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(12), cfg);
        let total = SEGMENT_MAX_CHUNKS * 5;
        for i in 0..total {
            w.push(Direction::Stdout, format!("{i}\n").as_bytes())
                .expect("a ring never refuses");
        }
        assert_eq!(w.refused_chunks(), 0, "a cap prunes, it never refuses");
        assert!(w.evicted_chunks() > 0);

        let manifest = w.seal();
        assert!(manifest.is_truncated(), "a windowed capture says so");
        assert_eq!(manifest.retention, RetentionPolicy::Ring);
        assert_eq!(
            manifest.evicted_chunks + manifest.chunks.len() as u64,
            total,
            "every chunk is either still held or accounted as evicted"
        );
        let last = manifest.chunks.last().expect("a live window");
        assert_eq!(last.seq, total - 1, "the newest write always survives");

        verify_sealed_root(&manifest).expect("the surviving window seals a valid root");
        verify_chunks(&manifest, dir.path()).expect("the surviving segments verify");
        let out = export(&manifest, dir.path(), &fixed_key(12)).expect("export the window");
        assert!(out.ends_with(format!("{}\n", total - 1).as_bytes()));
    }

    #[test]
    fn an_evicted_window_keeps_its_sequence_numbers_and_its_anchor() {
        // A gap must read as a gap: sequence numbers cannot restart, and the
        // first surviving record must still name the chunk before it so a
        // verifier has an anchor rather than a fake genesis.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = writer_config();
        cfg.retention = RetentionPolicy::Ring;
        cfg.bounds = CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes: u64::MAX,
            max_chunks: SEGMENT_MAX_CHUNKS,
        };
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(13), cfg);
        for i in 0..(SEGMENT_MAX_CHUNKS * 3) {
            w.push(Direction::Stdout, format!("{i}").as_bytes())
                .expect("push");
        }
        let manifest = w.seal();
        let first = manifest.chunks.first().expect("a live window");
        assert!(first.seq > 0, "the window starts where the capture got to");
        assert_ne!(
            first.prev_hash,
            "0".repeat(64),
            "a pruned window must not claim to be genesis"
        );
    }

    #[test]
    fn hiding_the_eviction_count_breaks_the_sealed_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = writer_config();
        cfg.retention = RetentionPolicy::Ring;
        cfg.bounds = CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes: u64::MAX,
            max_chunks: SEGMENT_MAX_CHUNKS,
        };
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(14), cfg);
        for _ in 0..(SEGMENT_MAX_CHUNKS * 3) {
            w.push(Direction::Stdout, b"x").expect("push");
        }
        let mut manifest = w.seal();
        assert!(manifest.evicted_chunks > 0);
        manifest.evicted_chunks = 0;
        manifest.evicted_bytes = 0;
        assert_eq!(
            verify_sealed_root(&manifest),
            Err(TranscriptError::SealedRootMismatch)
        );
    }

    #[test]
    fn restating_a_ring_capture_as_fail_closed_breaks_the_sealed_root() {
        // A windowed artifact relabelled as one that would have refused reads
        // as a complete capture of a quiet workload. The root commits to the
        // policy so that relabelling cannot happen quietly.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = writer_config();
        cfg.retention = RetentionPolicy::Ring;
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(15), cfg);
        w.push(Direction::Stdout, b"out").expect("push");
        let mut manifest = w.seal();
        manifest.retention = RetentionPolicy::FailClosed;
        assert_eq!(
            verify_sealed_root(&manifest),
            Err(TranscriptError::SealedRootMismatch)
        );
    }

    #[test]
    fn a_ring_capture_bounds_its_file_count_as_well_as_its_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = writer_config();
        cfg.retention = RetentionPolicy::Ring;
        cfg.bounds = CaptureBounds {
            max_duration_secs: u64::MAX,
            max_bytes: u64::MAX,
            max_chunks: 4 * SEGMENT_MAX_CHUNKS,
        };
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(16), cfg);
        for _ in 0..(SEGMENT_MAX_CHUNKS * 20) {
            w.push(Direction::Stdout, b"x").expect("push");
        }
        // The live window spans at most `max_chunks / SEGMENT_MAX_CHUNKS`
        // sealed segments plus the open one; eviction unlinks the rest.
        assert!(
            w.segment_count() <= 6,
            "20k chunks left {} segments live",
            w.segment_count()
        );
        assert_eq!(files_in(dir.path()), w.segment_count());
    }
}
