//! Forensic transcript capture — sealed manifest format, bounded-capture
//! budget, and tamper verification.
//!
//! This is the integrity + bounds core only: it defines the on-disk manifest
//! for sealed transcript chunks, a fail-closed capture budget, and a verifier
//! that re-hashes chunks against the manifest. The capture sink, at-rest
//! payload encryption, and the operator CLI build on these types — raw payloads
//! are never written to the normal audit chain, and capture is opt-in and
//! bounded.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

use crate::crypto::aead;

/// Filename of the host transcript key-encryption key, under the keys dir.
pub const TRANSCRIPT_KEK_FILENAME: &str = "transcript-kek.bin";

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
    /// True when the frame was denied by egress policy (dropped, not forwarded)
    /// rather than crossing the boundary — forensically the interesting case (an
    /// attempt to reach a blocked endpoint). `#[serde(default)]` so manifests
    /// written before this field parse as `false` (forwarded).
    #[serde(default)]
    pub dropped: bool,
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
    #[error("chunk {seq} ({file}) failed to decrypt (wrong key or tampered ciphertext)")]
    Decrypt { seq: u64, file: String },
    #[error("wrapped transcript key is malformed or cannot be unwrapped")]
    WrappedKeyInvalid,
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

/// Bounded, AEAD-encrypting transcript writer. Each pushed payload is checked
/// against the [`CaptureBudget`] *before* it is written, encrypted at rest with
/// the per-capture data key, and recorded in the manifest by the sha256 of its
/// **ciphertext** (so [`verify_chunks`] re-hashes what is on disk). The raw
/// data key is the caller's to wrap for `recipient`; the writer only records
/// the already-wrapped form.
pub struct TranscriptWriter {
    dir: PathBuf,
    key: aead::Key,
    budget: CaptureBudget,
    chunks: Vec<ChunkRecord>,
    capture_id: String,
    binding: CaptureBinding,
    bounds: CaptureBounds,
    created_unix_secs: u64,
    wrapped_data_key_b64: String,
    recipient: String,
}

/// Construction parameters for a [`TranscriptWriter`] (grouped to keep the
/// constructor narrow). `wrapped_data_key_b64` is the per-capture key wrapped
/// for `recipient`; the writer records it verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptWriterConfig {
    pub capture_id: String,
    pub binding: CaptureBinding,
    pub bounds: CaptureBounds,
    pub created_unix_secs: u64,
    pub recipient: String,
    pub wrapped_data_key_b64: String,
}

impl TranscriptWriter {
    /// `dir` must already exist. `key` encrypts chunks at rest.
    pub fn new(dir: impl Into<PathBuf>, key: aead::Key, config: TranscriptWriterConfig) -> Self {
        Self {
            dir: dir.into(),
            key,
            budget: CaptureBudget::new(config.bounds),
            chunks: Vec::new(),
            capture_id: config.capture_id,
            binding: config.binding,
            bounds: config.bounds,
            created_unix_secs: config.created_unix_secs,
            wrapped_data_key_b64: config.wrapped_data_key_b64,
            recipient: config.recipient,
        }
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

    fn push_inner(
        &mut self,
        direction: Direction,
        dropped: bool,
        plaintext: &[u8],
    ) -> Result<(), TranscriptError> {
        self.budget.try_add(plaintext.len() as u64)?;
        let seq = self.chunks.len() as u64;
        let file = format!("{seq}.chunk");
        let ciphertext = aead::seal(&self.key, plaintext);
        let path = self.dir.join(&file);
        std::fs::write(&path, &ciphertext).map_err(|e| TranscriptError::Io {
            file: file.clone(),
            msg: e.to_string(),
        })?;
        let sha256_hex =
            crate::crypto::image_verify::sha256_file(&path).map_err(|e| TranscriptError::Io {
                file: file.clone(),
                msg: e.to_string(),
            })?;
        self.chunks.push(ChunkRecord {
            seq,
            file,
            sha256_hex,
            size_bytes: ciphertext.len() as u64,
            direction,
            dropped,
        });
        Ok(())
    }

    /// Finalize the manifest for the chunks written so far.
    pub fn seal(self) -> TranscriptManifest {
        TranscriptManifest {
            format_version: TRANSCRIPT_MANIFEST_FORMAT_VERSION,
            capture_id: self.capture_id,
            binding: self.binding,
            bounds: self.bounds,
            created_unix_secs: self.created_unix_secs,
            wrapped_data_key_b64: self.wrapped_data_key_b64,
            recipient: self.recipient,
            chunks: self.chunks,
        }
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
    verify_chunks(manifest, dir)?;
    let mut out = Vec::new();
    for c in &manifest.chunks {
        let ciphertext = std::fs::read(dir.join(&c.file)).map_err(|e| TranscriptError::Io {
            file: c.file.clone(),
            msg: e.to_string(),
        })?;
        let plaintext = aead::open(key, &ciphertext).map_err(|_| TranscriptError::Decrypt {
            seq: c.seq,
            file: c.file.clone(),
        })?;
        out.extend_from_slice(&plaintext);
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
            dropped: false,
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
            dropped: false,
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
            dropped: false,
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
            dropped: false,
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
            created_unix_secs: 1,
            recipient: "host-key-1".to_string(),
            wrapped_data_key_b64: "wrapped".to_string(),
        }
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
    fn export_fails_closed_on_a_tampered_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = TranscriptWriter::new(dir.path(), fixed_key(7), writer_config());
        w.push(Direction::Egress, b"secret").unwrap();
        let manifest = w.seal();
        // Flip a byte in place (same length) so the hash check — not the size
        // check — is what refuses.
        let mut ct = std::fs::read(dir.path().join("0.chunk")).unwrap();
        ct[0] ^= 0xff;
        std::fs::write(dir.path().join("0.chunk"), &ct).unwrap();
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
            !dir.path().join("0.chunk").exists(),
            "no ciphertext lands when the budget refuses the chunk"
        );
    }
}
