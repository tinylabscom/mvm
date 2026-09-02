//! Idempotent extraction of embedded host-vm binaries to a
//! content-hashed dir under the supplied cache root (typically
//! `~/.mvm/cache/host-bins`). Re-verifies each binary's SHA-256
//! against the embedded constant on every call — a corrupted or
//! tampered on-disk cache fails closed.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::embedded::EMBEDDED;

/// Refuse before touching the cache when this binary carries no payload.
///
/// Without this the empty table extracts an empty directory and every caller
/// fails later, somewhere else, as a missing file — the failure would be read
/// as a corrupted cache rather than as a build that was never asked to embed
/// anything.
fn require_embedded_payload() -> std::io::Result<()> {
    if !EMBEDDED.is_empty() {
        return Ok(());
    }
    Err(std::io::Error::other(no_payload_message(cfg!(
        debug_assertions
    ))))
}

/// The refusal, naming the rebuild for *this* binary's profile.
///
/// Bare `just embed` writes `target/debug/mvmctl`, so a release-profile binary
/// sent to it is never replaced — and a `PATH` carrying `target/release` ahead
/// of `target/debug` keeps resolving to the one that refused. The profile has
/// to travel with the instruction or the instruction cannot work.
fn no_payload_message(debug_profile: bool) -> String {
    let (profile, binary) = if debug_profile {
        ("", "./target/debug/mvmctl")
    } else {
        (" --release", "./target/release/mvmctl")
    };
    format!(
        "this mvmctl was built without the embedded Linux host binaries, so it \
         cannot bootstrap a builder VM. Rebuild and invoke the same profile: \
         `just embed{profile}` then `{binary}` (or \
         `cargo build{profile} --features embed-host-bins`). Official release \
         binaries always carry them. Invoke the rebuilt path explicitly so PATH \
         cannot select the other profile."
    )
}

pub fn ensure_extracted(cache_root: &Path) -> std::io::Result<PathBuf> {
    require_embedded_payload()?;
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

pub struct BootHostBinaries {
    pub dir: PathBuf,
    pub stage0_init: Vec<u8>,
}

pub fn ensure_boot_host_binaries(cache_root: &Path) -> anyhow::Result<BootHostBinaries> {
    let dir = ensure_extracted(cache_root)
        .map_err(|e| anyhow::anyhow!("extract embedded host-vm binaries: {e}"))?;
    let stage0_init = std::fs::read(dir.join("stage0-init"))
        .map_err(|e| anyhow::anyhow!("read embedded stage0-init: {e}"))?;
    Ok(BootHostBinaries { dir, stage0_init })
}

fn combined_hash_hex() -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for bin in EMBEDDED.iter() {
        h.update(bin.name.as_bytes());
        h.update(bin.sha256_hex.as_bytes());
    }
    hex::encode(h.finalize())
}

fn verify_sha(path: &Path, expected_hex: &str) -> std::io::Result<bool> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()) == expected_hex)
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
        .expect("system clock is after unix epoch")
        .as_nanos();
    format!("{n:x}")
}

#[cfg(test)]
mod tests {
    use super::{combined_hash_hex, no_payload_message};

    #[test]
    fn combined_hash_is_sha256_hex() {
        let hash = combined_hash_hex();
        assert_eq!(hash.len(), 64);
        assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    /// A release-profile binary told to run bare `just embed` gets a *debug*
    /// binary, which never replaces the one that refused — so the same refusal
    /// returns forever.
    #[test]
    fn a_release_build_is_told_to_rebuild_the_release_profile() {
        let msg = no_payload_message(false);
        assert!(msg.contains("just embed --release"), "{msg}");
        assert!(msg.contains("./target/release/mvmctl"), "{msg}");
        assert!(
            msg.contains("cargo build --release --features embed-host-bins"),
            "{msg}"
        );
    }

    #[test]
    fn a_debug_build_is_told_to_rebuild_the_debug_profile() {
        let msg = no_payload_message(true);
        assert!(msg.contains("just embed"), "{msg}");
        assert!(msg.contains("./target/debug/mvmctl"), "{msg}");
        assert!(!msg.contains("--release"), "{msg}");
    }
}
