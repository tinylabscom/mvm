//! Forensic transcript capture — sealed manifest format, bounded-capture
//! budget, and tamper verification.
//!
//! This is the integrity + bounds core only: it defines the on-disk manifest
//! for sealed transcript chunks, a fail-closed capture budget, and a verifier
//! that re-hashes chunks against the manifest. The capture sink, at-rest
//! payload encryption, and the operator CLI build on these types — raw payloads
//! are never written to the normal audit chain, and capture is opt-in and
//! bounded.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Current sealed-transcript manifest format. Unknown versions fail closed.
pub const TRANSCRIPT_MANIFEST_FORMAT_VERSION: u32 = 1;

/// Direction of a captured chunk relative to the workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Egress,
    Ingress,
}

/// One sealed transcript chunk recorded in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkRecord {
    pub seq: u64,
    /// In-store filename, relative to the manifest directory. No path
    /// components — verification rejects anything containing `/`, `\`, or `..`.
    pub file: String,
    pub sha256_hex: String,
    pub size_bytes: u64,
    pub direction: Direction,
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
    pub chunks: Vec<ChunkRecord>,
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
    #[error("chunk {seq} ({file}) size mismatch: manifest {declared}, on-disk {actual}")]
    SizeMismatch {
        seq: u64,
        file: String,
        declared: u64,
        actual: u64,
    },
    #[error("chunk {seq} ({file}) hash mismatch (tampered)")]
    HashMismatch { seq: u64, file: String },
    #[error("unsafe chunk filename {0:?} (path components not allowed)")]
    UnsafeChunkName(String),
    #[error("io error verifying {file}: {msg}")]
    Io { file: String, msg: String },
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

/// Verify every manifest chunk against its on-disk file (size + sha256). Fails
/// closed on an unknown format version, an unsafe filename, or a missing,
/// oversized, or tampered chunk. Integrity only — does not decrypt.
pub fn verify_chunks(manifest: &TranscriptManifest, dir: &Path) -> Result<(), TranscriptError> {
    if manifest.format_version != TRANSCRIPT_MANIFEST_FORMAT_VERSION {
        return Err(TranscriptError::UnknownFormatVersion {
            got: manifest.format_version,
            expected: TRANSCRIPT_MANIFEST_FORMAT_VERSION,
        });
    }
    for c in &manifest.chunks {
        if c.file.is_empty()
            || c.file.contains('/')
            || c.file.contains('\\')
            || c.file == "."
            || c.file == ".."
        {
            return Err(TranscriptError::UnsafeChunkName(c.file.clone()));
        }
        let path = dir.join(&c.file);
        let meta = std::fs::metadata(&path).map_err(|_| TranscriptError::MissingChunk {
            seq: c.seq,
            file: c.file.clone(),
        })?;
        if meta.len() != c.size_bytes {
            return Err(TranscriptError::SizeMismatch {
                seq: c.seq,
                file: c.file.clone(),
                declared: c.size_bytes,
                actual: meta.len(),
            });
        }
        let got =
            crate::crypto::image_verify::sha256_file(&path).map_err(|e| TranscriptError::Io {
                file: c.file.clone(),
                msg: e.to_string(),
            })?;
        if got != c.sha256_hex {
            return Err(TranscriptError::HashMismatch {
                seq: c.seq,
                file: c.file.clone(),
            });
        }
    }
    Ok(())
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
        TranscriptManifest {
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
            chunks,
        }
    }

    fn write_chunk(dir: &Path, name: &str, body: &[u8]) -> ChunkRecord {
        std::fs::write(dir.join(name), body).unwrap();
        let sha = crate::crypto::image_verify::sha256_file(&dir.join(name)).unwrap();
        ChunkRecord {
            seq: 0,
            file: name.to_string(),
            sha256_hex: sha,
            size_bytes: body.len() as u64,
            direction: Direction::Egress,
        }
    }

    #[test]
    fn manifest_serde_roundtrips() {
        let m = manifest(vec![ChunkRecord {
            seq: 0,
            file: "0.bin".to_string(),
            sha256_hex: "ab".to_string(),
            size_bytes: 2,
            direction: Direction::Ingress,
        }]);
        let json = serde_json::to_string(&m).unwrap();
        let back: TranscriptManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
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
            sha256_hex: "00".to_string(),
            size_bytes: 1,
            direction: Direction::Egress,
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
            sha256_hex: "00".to_string(),
            size_bytes: 1,
            direction: Direction::Egress,
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
}
