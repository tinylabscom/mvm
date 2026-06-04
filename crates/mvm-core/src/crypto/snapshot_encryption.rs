//! Plan 63 W5 — chunked AES-256-GCM for snapshot artifacts.
//!
//! `crate::crypto::snapshot_crypto` provides AES-256-GCM over byte
//! slices. Snapshots can be multi-GB, so this module adds the
//! file-bound, chunked wrapper the pause/resume pipeline needs:
//!
//! - Reads plaintext from `<artifact>` in `CHUNK_SIZE`-byte chunks.
//! - Each chunk is encrypted under a fresh 96-bit nonce.
//! - Writes a small fixed header + N encrypted chunks to a sibling
//!   ciphertext file, then atomically renames over the plaintext.
//!
//! ## Wire format
//!
//! ```text
//! ┌────────────────────────────────────────────────────┐
//! │ Header (24 bytes)                                  │
//! │   magic       : 4 bytes  = b"MVSE"  (MVm Snapshot │
//! │                                       Encrypted)  │
//! │   version     : 1 byte   = SCHEMA_VERSION         │
//! │   reserved    : 3 bytes  = 0                      │
//! │   chunk_size  : 4 bytes  LE u32                   │
//! │   pt_size     : 8 bytes  LE u64 (plaintext size)  │
//! │   reserved2   : 4 bytes  = 0                      │
//! ├────────────────────────────────────────────────────┤
//! │ Chunk 1  (chunk_size + 28 bytes)                   │
//! │   nonce : 12 bytes                                │
//! │   ct+tag: chunk_size + 16 bytes                   │
//! ├────────────────────────────────────────────────────┤
//! │ Chunk 2  (chunk_size + 28 bytes)                   │
//! │   …                                                │
//! ├────────────────────────────────────────────────────┤
//! │ Final chunk (≤ chunk_size + 28 bytes)              │
//! │   nonce + ct+tag for the trailing partial chunk    │
//! └────────────────────────────────────────────────────┘
//! ```
//!
//! The plaintext file size is recorded in the header so the
//! decoder can validate after stitching the chunks. Mismatch is
//! an error — protects against silent truncation.
//!
//! ## What this module does NOT do
//!
//! - **Authenticate the header.** The header's integrity is the
//!   responsibility of [`snapshot_hmac`] — which already HMACs the
//!   whole sealed bundle.
//! - **Manage the DEK.** Caller supplies a 32-byte key; key
//!   provisioning is `KeyProvider`'s job (plan 63 W3).
//! - **Decide whether to encrypt.** Caller (the pause/resume
//!   pipeline) chooses based on whether a tenant DEK is
//!   available.

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use rand::RngCore;

/// Default plaintext chunk size: 1 MiB. Each on-disk encrypted
/// chunk is `chunk_size + 28` bytes (12 nonce + 16 tag).
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// 12-byte nonce per AES-256-GCM convention.
pub const NONCE_SIZE: usize = 12;

/// 16-byte AES-GCM authentication tag.
pub const TAG_SIZE: usize = 16;

/// 32-byte AES-256 key.
pub const KEY_SIZE: usize = 32;

/// File header magic; lets the resume path probe for "is this file
/// encrypted?" cheaply.
pub const MAGIC: &[u8; 4] = b"MVSE";

/// On-disk header schema version. Bumps invalidate existing
/// snapshots; the v1 → v2 migration documented in ADR-039 is the
/// only break planned today.
pub const SCHEMA_VERSION: u8 = 1;

/// Header size on disk (bytes). Fixed across schema versions
/// because newer schemas extend via Sidecar fields rather than
/// growing the header.
pub const HEADER_SIZE: usize = 24;

/// Encrypt `plaintext_path` under `key` into a ciphertext file,
/// then atomically rename over the plaintext.
///
/// Uses [`DEFAULT_CHUNK_SIZE`] chunks. On a clean run the original
/// plaintext is removed (replaced by the ciphertext); on an error
/// the original is left intact and any partial ciphertext is
/// cleaned up.
pub fn encrypt_file_in_place(path: &Path, key: &[u8]) -> Result<()> {
    encrypt_file_in_place_with_chunk_size(path, key, DEFAULT_CHUNK_SIZE)
}

/// Variant that lets tests pin a small chunk size to exercise the
/// multi-chunk path without committing megabytes of fixture data.
pub fn encrypt_file_in_place_with_chunk_size(
    path: &Path,
    key: &[u8],
    chunk_size: usize,
) -> Result<()> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "snapshot encryption key must be {KEY_SIZE} bytes, got {}",
            key.len()
        );
    }
    if chunk_size == 0 || chunk_size > u32::MAX as usize {
        anyhow::bail!("chunk_size must be in 1..=u32::MAX, got {chunk_size}");
    }

    let plaintext_meta =
        fs::metadata(path).with_context(|| format!("stat plaintext {}", path.display()))?;
    let pt_size = plaintext_meta.len();

    let tmp_path = path.with_extension("enc.tmp");
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("constructing AES-256-GCM cipher: {e}"))?;

    // Wrap the write in a closure so we can clean up on any error.
    let result: Result<()> = (|| {
        let plaintext_file =
            File::open(path).with_context(|| format!("opening plaintext {}", path.display()))?;
        let mut reader = BufReader::new(plaintext_file);

        let tmp_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("creating tmp {}", tmp_path.display()))?;
        let mut writer = BufWriter::new(tmp_file);

        // Header.
        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(MAGIC);
        header[4] = SCHEMA_VERSION;
        // bytes 5..8 reserved 0
        header[8..12].copy_from_slice(&(chunk_size as u32).to_le_bytes());
        header[12..20].copy_from_slice(&pt_size.to_le_bytes());
        // bytes 20..24 reserved 0
        writer
            .write_all(&header)
            .with_context(|| format!("writing header to {}", tmp_path.display()))?;

        // Chunks.
        let mut buf = vec![0u8; chunk_size];
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        let mut written_pt: u64 = 0;
        loop {
            let n = read_exact_up_to(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ct = cipher
                .encrypt(nonce, &buf[..n])
                .map_err(|e| anyhow::anyhow!("AES-256-GCM encrypt chunk: {e}"))?;
            writer
                .write_all(&nonce_bytes)
                .with_context(|| format!("writing chunk nonce to {}", tmp_path.display()))?;
            writer
                .write_all(&ct)
                .with_context(|| format!("writing chunk ciphertext to {}", tmp_path.display()))?;
            written_pt += n as u64;
            if n < chunk_size {
                break;
            }
        }

        if written_pt != pt_size {
            anyhow::bail!(
                "encrypt read {} bytes from plaintext but stat reported {} \
                 (file shrunk during encrypt?)",
                written_pt,
                pt_size
            );
        }

        writer.flush().ok();
        let f = writer.into_inner().context("flush BufWriter")?;
        f.sync_all().ok();
        Ok(())
    })();

    match result {
        Ok(()) => {
            fs::rename(&tmp_path, path).with_context(|| {
                format!("atomic rename {} → {}", tmp_path.display(), path.display())
            })?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Read up to `buf.len()` bytes from `reader` into `buf`. Returns
/// the number of bytes actually read (0 at EOF). Unlike
/// `Read::read_exact`, partial reads at EOF are reported rather
/// than treated as errors.
fn read_exact_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = reader
            .read(&mut buf[total..])
            .context("reading plaintext chunk")?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

/// Decrypt `path` under `key` in place. Inverse of
/// [`encrypt_file_in_place`].
///
/// Validates the magic, schema version, and stitched plaintext
/// size against the header.
pub fn decrypt_file_in_place(path: &Path, key: &[u8]) -> Result<()> {
    if key.len() != KEY_SIZE {
        anyhow::bail!(
            "snapshot encryption key must be {KEY_SIZE} bytes, got {}",
            key.len()
        );
    }
    let header = read_header(path)?;
    let tmp_path = path.with_extension("dec.tmp");
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("constructing AES-256-GCM cipher: {e}"))?;

    let result: Result<()> = (|| {
        let ct_file =
            File::open(path).with_context(|| format!("opening ciphertext {}", path.display()))?;
        let mut reader = BufReader::new(ct_file);
        // Skip the header — we've already parsed it.
        let mut hdr_skip = [0u8; HEADER_SIZE];
        reader
            .read_exact(&mut hdr_skip)
            .context("skipping header on decrypt")?;

        let tmp_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .with_context(|| format!("creating tmp {}", tmp_path.display()))?;
        let mut writer = BufWriter::new(tmp_file);

        let chunk_input_size = header.chunk_size as usize + TAG_SIZE;
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        let mut ct_buf = vec![0u8; chunk_input_size];
        let mut written_pt: u64 = 0;
        loop {
            match reader.read_exact(&mut nonce_bytes) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => {
                    return Err(anyhow::anyhow!("reading chunk nonce: {e}"));
                }
            }
            let n = read_exact_up_to(&mut reader, &mut ct_buf)?;
            if n < TAG_SIZE {
                anyhow::bail!(
                    "ciphertext chunk truncated: got {n} bytes after nonce \
                     (minimum {TAG_SIZE} for AEAD tag)"
                );
            }
            let nonce = Nonce::from_slice(&nonce_bytes);
            let pt = cipher.decrypt(nonce, &ct_buf[..n]).map_err(|_| {
                anyhow::anyhow!(
                    "AES-256-GCM authentication failure — wrong key or tampered ciphertext"
                )
            })?;
            writer
                .write_all(&pt)
                .with_context(|| format!("writing plaintext chunk to {}", tmp_path.display()))?;
            written_pt += pt.len() as u64;
        }

        if written_pt != header.pt_size {
            anyhow::bail!(
                "decrypted size {} != declared plaintext size {} (truncated or corrupted)",
                written_pt,
                header.pt_size
            );
        }
        writer.flush().ok();
        let f = writer.into_inner().context("flush BufWriter")?;
        f.sync_all().ok();
        Ok(())
    })();

    match result {
        Ok(()) => {
            fs::rename(&tmp_path, path).with_context(|| {
                format!("atomic rename {} → {}", tmp_path.display(), path.display())
            })?;
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Snapshot encryption header — what [`read_header`] returns.
#[derive(Debug, Clone, Copy)]
pub struct EncryptionHeader {
    pub version: u8,
    pub chunk_size: u32,
    pub pt_size: u64,
}

/// Probe a file's encryption status. Returns `Some(header)` if
/// the file begins with the `MVSE` magic, `None` otherwise. Cheap —
/// reads only the first 24 bytes.
pub fn probe(path: &Path) -> Result<Option<EncryptionHeader>> {
    if !path.exists() {
        return Ok(None);
    }
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.len() < HEADER_SIZE as u64 {
        return Ok(None);
    }
    let mut buf = [0u8; HEADER_SIZE];
    let mut f =
        File::open(path).with_context(|| format!("opening {} for probe", path.display()))?;
    f.read_exact(&mut buf)
        .with_context(|| format!("reading header from {}", path.display()))?;
    if &buf[0..4] != MAGIC {
        return Ok(None);
    }
    let version = buf[4];
    let chunk_size = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let pt_size = u64::from_le_bytes(buf[12..20].try_into().unwrap());
    Ok(Some(EncryptionHeader {
        version,
        chunk_size,
        pt_size,
    }))
}

/// Read + validate the header, returning the parsed fields. Errors
/// when the magic / version don't match expectations.
fn read_header(path: &Path) -> Result<EncryptionHeader> {
    let header = probe(path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is not a snapshot-encrypted file (missing MVSE magic)",
            path.display()
        )
    })?;
    if header.version != SCHEMA_VERSION {
        anyhow::bail!(
            "{} has encryption schema version {}, agent only knows {SCHEMA_VERSION}",
            path.display(),
            header.version
        );
    }
    if header.chunk_size == 0 {
        anyhow::bail!("{} declared chunk_size = 0 (invalid)", path.display());
    }
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_SIZE] {
        [0xAA; KEY_SIZE]
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
    }

    fn read_file(path: &Path) -> Vec<u8> {
        fs::read(path).unwrap()
    }

    #[test]
    fn round_trip_under_one_chunk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.bin");
        let plaintext = b"hello world, this is one tiny chunk".to_vec();
        write_file(&path, &plaintext);

        encrypt_file_in_place(&path, &test_key()).unwrap();
        // Encrypted file must NOT contain the plaintext.
        let ct = read_file(&path);
        assert!(!ct.windows(11).any(|w| w == b"hello world"));
        // Magic check.
        assert_eq!(&ct[0..4], MAGIC);

        decrypt_file_in_place(&path, &test_key()).unwrap();
        assert_eq!(read_file(&path), plaintext);
    }

    #[test]
    fn round_trip_multi_chunk_uses_distinct_nonces() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.bin");
        // 3.5 chunks at chunk_size=64: produce 4 chunks (3 full + 1
        // partial). Tiny chunk size exercises the multi-chunk path
        // without burning megabytes.
        let plaintext = vec![0x42u8; 64 * 3 + 32];
        write_file(&path, &plaintext);

        encrypt_file_in_place_with_chunk_size(&path, &test_key(), 64).unwrap();
        let ct = read_file(&path);
        // Header (24) + 3 full chunks (64+12+16 = 92 each = 276) + 1
        // partial chunk (32+12+16 = 60) = 360 total.
        assert_eq!(ct.len(), HEADER_SIZE + 3 * (64 + 28) + (32 + 28));

        // Pull out the nonces (bytes 24..36, 24+92..24+92+12, etc.)
        // and assert they're all distinct — fresh nonce per chunk.
        let chunk_full = 64 + 28;
        let n1 = &ct[HEADER_SIZE..HEADER_SIZE + NONCE_SIZE];
        let n2 = &ct[HEADER_SIZE + chunk_full..HEADER_SIZE + chunk_full + NONCE_SIZE];
        let n3 = &ct[HEADER_SIZE + chunk_full * 2..HEADER_SIZE + chunk_full * 2 + NONCE_SIZE];
        let n4 = &ct[HEADER_SIZE + chunk_full * 3..HEADER_SIZE + chunk_full * 3 + NONCE_SIZE];
        assert_ne!(n1, n2);
        assert_ne!(n2, n3);
        assert_ne!(n3, n4);

        decrypt_file_in_place(&path, &test_key()).unwrap();
        assert_eq!(read_file(&path), plaintext);
    }

    #[test]
    fn round_trip_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("empty.bin");
        write_file(&path, b"");
        encrypt_file_in_place(&path, &test_key()).unwrap();
        let ct = read_file(&path);
        // Empty plaintext encodes as header-only (no chunks).
        assert_eq!(ct.len(), HEADER_SIZE);
        assert_eq!(&ct[0..4], MAGIC);
        decrypt_file_in_place(&path, &test_key()).unwrap();
        assert_eq!(read_file(&path), b"");
    }

    #[test]
    fn round_trip_exactly_chunk_size_boundary() {
        // File whose size is an exact multiple of chunk_size — the
        // last chunk is "full". The encryptor used to have a bug
        // where it would write an empty trailing chunk; this test
        // pins the correct behavior.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("aligned.bin");
        let plaintext = vec![0x11u8; 64 * 2];
        write_file(&path, &plaintext);
        encrypt_file_in_place_with_chunk_size(&path, &test_key(), 64).unwrap();
        let ct = read_file(&path);
        // Header + 2 full chunks = 24 + 2*(64+28) = 208.
        assert_eq!(ct.len(), HEADER_SIZE + 2 * (64 + 28));
        decrypt_file_in_place(&path, &test_key()).unwrap();
        assert_eq!(read_file(&path), plaintext);
    }

    #[test]
    fn decrypt_rejects_wrong_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.bin");
        write_file(&path, b"sensitive bytes");
        encrypt_file_in_place(&path, &test_key()).unwrap();

        let mut wrong = test_key();
        wrong[0] ^= 0xFF;
        let err = decrypt_file_in_place(&path, &wrong).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("authentication failure") || s.contains("tampered"),
            "want auth failure context, got: {s}"
        );
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.bin");
        write_file(&path, &vec![0u8; 1024]);
        encrypt_file_in_place(&path, &test_key()).unwrap();

        // Flip one byte deep inside the first chunk's ciphertext
        // (past the header + nonce).
        let mut ct = read_file(&path);
        let target = HEADER_SIZE + NONCE_SIZE + 64;
        assert!(ct.len() > target);
        ct[target] ^= 0xFF;
        fs::write(&path, &ct).unwrap();

        let err = decrypt_file_in_place(&path, &test_key()).unwrap_err();
        assert!(err.to_string().contains("authentication failure"));
    }

    #[test]
    fn decrypt_rejects_truncated_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.bin");
        write_file(&path, b"some plaintext here");
        encrypt_file_in_place(&path, &test_key()).unwrap();
        let mut ct = read_file(&path);
        ct.truncate(ct.len() - 5); // chop the tail
        fs::write(&path, &ct).unwrap();
        assert!(decrypt_file_in_place(&path, &test_key()).is_err());
    }

    #[test]
    fn probe_returns_none_for_unencrypted_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("plain.bin");
        write_file(&path, b"hello plaintext world");
        assert!(probe(&path).unwrap().is_none());
    }

    #[test]
    fn probe_returns_header_for_encrypted_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.bin");
        write_file(&path, &[1u8; 100]);
        encrypt_file_in_place(&path, &test_key()).unwrap();
        let header = probe(&path).unwrap().unwrap();
        assert_eq!(header.version, SCHEMA_VERSION);
        assert_eq!(header.chunk_size as usize, DEFAULT_CHUNK_SIZE);
        assert_eq!(header.pt_size, 100);
    }

    #[test]
    fn probe_returns_none_for_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(probe(&tmp.path().join("nope.bin")).unwrap().is_none());
    }

    #[test]
    fn encrypt_rejects_wrong_key_size() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.bin");
        write_file(&path, b"data");
        let short = [0u8; 16];
        let err = encrypt_file_in_place(&path, &short).unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn encrypt_failure_leaves_plaintext_intact() {
        // Pre-create the .enc.tmp so create_new fails; ensures the
        // cleanup path doesn't destroy the original.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("artifact.bin");
        write_file(&path, b"important plaintext");
        let blocker = path.with_extension("enc.tmp");
        write_file(&blocker, b"blocking");

        let err = encrypt_file_in_place(&path, &test_key()).unwrap_err();
        let _ = err; // any error is acceptable
        assert_eq!(read_file(&path), b"important plaintext");
        // Cleanup the blocker so the test's tmp drop is clean.
        let _ = fs::remove_file(&blocker);
    }
}
