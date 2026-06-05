//! Plan 141 / ADR-064 — append-only, length-prefixed flow-byte log.
//!
//! Record framing: `[u64 record_id LE][u32 len LE][len bytes payload]`.
//! The writer is per-VM; rotation is size-bounded by the caller. The audit
//! chain references records by `(file_name, record_id, sha256)` — payload
//! bytes never enter the chain (keeps it small + lets the chain stay
//! payload-free per Q8/claim 10). Files are mode 0600; the caller ensures
//! the parent dir is 0700 (~/.mvm posture, ADR-002 §W1.5).
//!
//! Encryption-at-rest is a deferred follow-up (own ADR); V1 is plaintext
//! on a 0600 file under a 0700 dir.

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Reference the audit chain stores for one logged record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRef {
    pub record_id: u64,
    pub sha256: String,
}

pub struct FlowByteLogWriter {
    file: std::fs::File,
    next_id: u64,
}

impl FlowByteLogWriter {
    /// Create (truncating) a new log file at `path`, mode 0600. The caller
    /// ensures the parent dir exists at 0700.
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self { file, next_id: 0 })
    }

    /// Append one record; returns its id + sha256 for the chain entry.
    pub fn append(&mut self, payload: &[u8]) -> std::io::Result<RecordRef> {
        let id = self.next_id;
        self.file.write_all(&id.to_le_bytes())?;
        let len = u32::try_from(payload.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "record exceeds u32 length",
            )
        })?;
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(payload)?;
        self.next_id += 1;
        let sha256 = {
            let mut h = Sha256::new();
            h.update(payload);
            hex::encode(h.finalize())
        };
        Ok(RecordRef {
            record_id: id,
            sha256,
        })
    }
}

/// Read back every record (test + forensics helper).
pub fn read_all_records(path: &Path) -> std::io::Result<Vec<Vec<u8>>> {
    let mut f = std::fs::File::open(path)?;
    let mut out = Vec::new();
    loop {
        let mut idbuf = [0u8; 8];
        match f.read_exact(&mut idbuf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let mut lenbuf = [0u8; 4];
        f.read_exact(&mut lenbuf)?;
        let len = u32::from_le_bytes(lenbuf) as usize;
        let mut payload = vec![0u8; len];
        f.read_exact(&mut payload)?;
        out.push(payload);
    }
    Ok(out)
}

/// Retention sweep: delete flow-byte files whose mtime is older than
/// `max_age_days` under `root` (`~/.mvm/audit/flow-bytes`, with one
/// per-tenant subdir). Returns the number of files removed. Called from
/// `mvmctl cache prune`.
pub fn sweep_retention(root: &Path, max_age_days: u32) -> std::io::Result<u64> {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(max_age_days as u64 * 86_400))
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut removed = 0u64;
    let Ok(tenants) = std::fs::read_dir(root) else {
        return Ok(0);
    };
    for tenant in tenants.flatten() {
        let Ok(files) = std::fs::read_dir(tenant.path()) else {
            continue;
        };
        for f in files.flatten() {
            if let Ok(meta) = f.metadata() {
                if let Ok(modified) = meta.modified() {
                    if modified < cutoff && std::fs::remove_file(f.path()).is_ok() {
                        removed += 1;
                    }
                }
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_then_read_back_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vm-a.bin");
        let mut w = FlowByteLogWriter::create(&path).unwrap();
        let rec = w.append(b"hello").unwrap();
        assert_eq!(rec.record_id, 0);
        assert_eq!(rec.sha256.len(), 64);
        let rec2 = w.append(b"world").unwrap();
        assert_eq!(rec2.record_id, 1);
        let records = read_all_records(&path).unwrap();
        assert_eq!(records, vec![b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn created_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vm-b.bin");
        let _ = FlowByteLogWriter::create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn sweep_boundary_removes_with_zero_window_keeps_with_large() {
        // std gives no portable mtime-setter, so assert the cutoff
        // boundary instead of backdating: max_age_days = 0 (cutoff = now)
        // removes files written before the sweep; a 10-year window keeps
        // them.
        let root = tempfile::tempdir().unwrap();
        let tenant_dir = root.path().join("acme");
        std::fs::create_dir_all(&tenant_dir).unwrap();
        let old = tenant_dir.join("vm-old.bin");
        let fresh = tenant_dir.join("vm-fresh.bin");
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&fresh, b"y").unwrap();
        let removed_all = sweep_retention(root.path(), 0).unwrap();
        assert_eq!(removed_all, 2, "cutoff=now removes both files");

        // Recreate and assert a large window keeps everything.
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&fresh, b"y").unwrap();
        let removed_none = sweep_retention(root.path(), 3650).unwrap();
        assert_eq!(removed_none, 0, "10-year window keeps both files");
    }

    #[test]
    fn sweep_missing_root_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert_eq!(sweep_retention(&missing, 7).unwrap(), 0);
    }
}
