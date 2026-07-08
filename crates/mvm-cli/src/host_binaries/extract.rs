//! Idempotent extraction of embedded host-vm binaries to a
//! content-hashed dir under the supplied cache root (typically
//! `~/.cache/mvm/host-bins`). Re-verifies each binary's SHA-256
//! against the embedded constant on every call — a corrupted or
//! tampered on-disk cache fails closed.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::embedded::EMBEDDED;
use super::source_build::{has_source_checkout, resolve_or_build_host_binaries};

pub fn ensure_extracted(cache_root: &Path) -> std::io::Result<PathBuf> {
    let combined_hash = combined_hash_hex();
    let target = cache_root.join(&combined_hash);
    std::fs::create_dir_all(&target)?;
    // Lock the parent + restrict its perms.
    let perm = std::fs::Permissions::from_mode(0o700);
    let _ = std::fs::set_permissions(cache_root, perm.clone());
    let _ = std::fs::set_permissions(&target, perm);

    for bin in EMBEDDED.iter() {
        let final_path = target.join(bin.name);
        if final_path.exists() && verify_sha(&final_path, bin.sha256_hex)? {
            continue;
        }
        write_atomic(&final_path, bin.bytes, 0o755)?;
        if !verify_sha(&final_path, bin.sha256_hex)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("post-extract SHA mismatch for {}", bin.name),
            ));
        }
    }
    Ok(target)
}

/// Like [`ensure_extracted`], but refuses a stub build — the zero-byte
/// binaries baked into non-release builds unless `MVM_EMBED_BINARIES=1`
/// overrides the fast path. Call this from any path that actually boots a VM
/// from the embedded binaries so a stub build fails fast with a clear message
/// instead of an opaque builder-VM boot failure.
pub fn ensure_extracted_for_boot(cache_root: &Path) -> std::io::Result<PathBuf> {
    if EMBEDDED.iter().any(|bin| bin.bytes.is_empty()) {
        if has_source_checkout() {
            return resolve_or_build_host_binaries(cache_root)
                .map_err(|e| std::io::Error::other(e.to_string()));
        }
        let stub = EMBEDDED
            .iter()
            .find(|bin| bin.bytes.is_empty())
            .expect("stub binary present when any embedded payload is empty");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "embedded host-vm binary `{}` is a zero-byte stub — this mvmctl was \
                 built without real embedded host binaries and has no source checkout to \
                 build them from",
                stub.name
            ),
        ));
    }
    ensure_extracted(cache_root)
}

fn combined_hash_hex() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for bin in EMBEDDED.iter() {
        h.update(bin.name.as_bytes());
        h.update(bin.sha256_hex.as_bytes());
    }
    format!("{:x}", h.finalize())
}

fn verify_sha(path: &Path, expected_hex: &str) -> std::io::Result<bool> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(format!("{:x}", h.finalize()) == expected_hex)
}

fn write_atomic(target: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = target.with_extension(format!("tmp.{}.{}", std::process::id(), rand_suffix()));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp, target)
}

fn rand_suffix() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{n:x}")
}
