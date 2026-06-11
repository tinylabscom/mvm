//! Verity sidecar generation for an ext4 image.
//!
//! `veritysetup format` produces a separate "hash device" (the
//! Merkle tree over the rootfs's data blocks) plus a root hash.
//! At boot, `mvm-verity-init` recomputes the Merkle tree and
//! asserts the root hash matches the value pinned on the kernel
//! cmdline. Any byte-level tamper of the rootfs panics the
//! kernel before userspace.
//!
//! ## Parameters (DO NOT CHANGE without updating `mvm-verity-init`)
//!
//! - `--data-block-size=1024` — must match the hard-coded
//!   constant in `mvm-guest/src/bin/mvm-verity-init.rs`. The
//!   comment there explains why we use 1 KiB blocks (matches
//!   mke2fs's default for sub-512 MiB images, lines up with
//!   ext4's device-block-size constraint).
//! - `--hash-block-size=4096` — veritysetup default; the hash
//!   tree's internal node size.
//! - `--salt=00…00` (64 hex zeros) — pinned for determinism.
//!   Any non-zero salt would tie the root hash to the salt,
//!   defeating the per-digest verity cache.
//! - `sha256` hash algorithm — what `mvm-verity-init` expects.
//!
//! ## Determinism story
//!
//! Two `seal_with_verity` runs against byte-identical inputs
//! produce byte-identical sidecars *and* identical root hashes.
//! This is the load-bearing invariant for the per-digest
//! verity cache. The integration tests assert it.
//!
//! ## Host support
//!
//! Linux-only at runtime. `veritysetup` is part of `cryptsetup`,
//! installed via the `e2fsprogs`-adjacent `cryptsetup-bin` package
//! (Debian/Ubuntu) or the `cryptsetup` package (Alpine, Fedora,
//! Arch). On macOS / Windows the function returns
//! [`OciUnpackError::HostUnsupported`]; the CLI orchestrator
//! routes through the libkrun builder VM.

use crate::oci_to_rootfs::error::OciUnpackError;
use crate::oci_to_rootfs::ext4::MaterializedRootfs;
use std::path::{Path, PathBuf};

/// `data-block-size` pinned to 1024 bytes. Must match the
/// `DATA_BLOCK_SIZE` constant in
/// `crates/mvm-guest/src/bin/mvm-verity-init.rs` or boot fails
/// with "metadata block 0 is corrupted" at the dm-verity layer.
pub const MVM_VERITY_DATA_BLOCK_SIZE: u32 = 1024;

/// `hash-block-size` pinned to 4096 bytes. Matches veritysetup's
/// own default; the kernel's verity target reads metadata at
/// this block size regardless of the data block size.
pub const MVM_VERITY_HASH_BLOCK_SIZE: u32 = 4096;

/// 64 hex characters of zero. Pinned salt is the load-bearing
/// determinism guarantee — any non-zero salt would couple the
/// root hash to the salt and defeat per-digest caching.
pub const MVM_VERITY_PINNED_SALT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// `sha256` hash algorithm. Must match
/// `mvm-verity-init.rs`'s expected algorithm.
pub const MVM_VERITY_HASH_ALGORITHM: &str = "sha256";

/// Pinned verity superblock UUID. Without `--uuid`, `veritysetup
/// format` embeds a random UUID in the sidecar header, which makes
/// two `seal_with_verity` runs against byte-identical inputs produce
/// non-byte-identical sidecars (the root hash is still deterministic,
/// but the per-digest verity cache compares sidecar bytes too).
/// Pinning it preserves the determinism invariant. The value is the same
/// shape as `Mke2fsOptions::default().uuid` so the two artifacts read
/// together coherently in diagnostics.
pub const MVM_VERITY_PINNED_UUID: &str = "00000000-0000-0000-0000-000000000003";

/// Knobs for [`seal_with_verity`]. Defaults are pinned to the
/// values `mvm-verity-init` expects at boot; callers can
/// override for tests but production paths should use
/// `Default::default()`.
#[derive(Debug, Clone)]
pub struct VeritysetupOptions {
    /// Data block size in bytes. See module docs for why this
    /// must be 1024 for compatibility with `mvm-verity-init`.
    pub data_block_size: u32,
    /// Hash tree internal block size. Default 4096
    /// (veritysetup default).
    pub hash_block_size: u32,
    /// Salt as 64 hex characters. Default is all-zero
    /// (`MVM_VERITY_PINNED_SALT`) to make the root hash a
    /// function of the rootfs bytes alone.
    pub salt: String,
    /// Hash algorithm. Default `sha256`.
    pub algorithm: String,
    /// UUID embedded in the verity sidecar superblock. Default
    /// is `MVM_VERITY_PINNED_UUID`; pinning it is what makes the
    /// sidecar byte-deterministic across runs (veritysetup
    /// generates a random UUID per call otherwise).
    pub uuid: String,
    /// Override the `veritysetup` binary location. Default
    /// `None` → resolved via `$PATH`. Tests use this to
    /// substitute a stub.
    pub veritysetup_binary: Option<PathBuf>,
}

impl Default for VeritysetupOptions {
    fn default() -> Self {
        Self {
            data_block_size: MVM_VERITY_DATA_BLOCK_SIZE,
            hash_block_size: MVM_VERITY_HASH_BLOCK_SIZE,
            salt: MVM_VERITY_PINNED_SALT.to_string(),
            algorithm: MVM_VERITY_HASH_ALGORITHM.to_string(),
            uuid: MVM_VERITY_PINNED_UUID.to_string(),
            veritysetup_binary: None,
        }
    }
}

/// Final descriptor produced by [`seal_with_verity`].
#[derive(Debug, Clone)]
pub struct VeritySealedRootfs {
    /// Path to the rootfs ext4 (unchanged from input).
    pub rootfs_path: PathBuf,
    /// Path to the verity hash device — the Merkle tree sidecar
    /// the kernel reads at boot.
    pub sidecar_path: PathBuf,
    /// Path to a text file containing the root hash as
    /// lowercase hex. The kernel cmdline gets the same hash via
    /// `mvm.roothash=<hex>`.
    pub roothash_path: PathBuf,
    /// Root hash itself, lowercase hex (typically 64 chars for
    /// sha256). The on-disk file at `roothash_path` carries the
    /// same string with a trailing newline.
    pub roothash: String,
    /// Algorithm used. Mirrored from options for diagnostics;
    /// always `sha256` today.
    pub algorithm: String,
    /// Data block size used. Mirrored from options for
    /// diagnostics; always `MVM_VERITY_DATA_BLOCK_SIZE` today.
    pub data_block_size: u32,
}

/// Seal `rootfs` with a verity sidecar.
///
/// Output paths default to siblings of `rootfs.rootfs_path`:
///
/// - `<rootfs-stem>.verity` for the hash device
/// - `<rootfs-stem>.roothash` for the text-file root hash
///
/// Linux-only at runtime; non-Linux hosts return
/// [`OciUnpackError::HostUnsupported`]. The CLI orchestrator
/// routes the macOS path through the libkrun builder VM.
pub fn seal_with_verity(
    rootfs: &MaterializedRootfs,
    options: &VeritysetupOptions,
) -> Result<VeritySealedRootfs, OciUnpackError> {
    validate_options(options)?;
    let (sidecar_path, roothash_path) = derive_output_paths(&rootfs.path);

    #[cfg(target_os = "linux")]
    {
        prepare_sidecar(&sidecar_path)?;
        let roothash = run_veritysetup_format(&rootfs.path, &sidecar_path, options)?;
        write_roothash_file(&roothash_path, &roothash)?;
        Ok(VeritySealedRootfs {
            rootfs_path: rootfs.path.clone(),
            sidecar_path,
            roothash_path,
            roothash,
            algorithm: options.algorithm.clone(),
            data_block_size: options.data_block_size,
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (sidecar_path, roothash_path);
        Err(OciUnpackError::HostUnsupported {
            operation: "verity sidecar generation (veritysetup format)",
            reason: "veritysetup is Linux-only; the W1.5 CLI orchestrator routes this through the libkrun builder VM (ADR-050)",
        })
    }
}

fn validate_options(options: &VeritysetupOptions) -> Result<(), OciUnpackError> {
    if options.salt.len() != 64 || !options.salt.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(OciUnpackError::VeritysetupFailed {
            reason: format!(
                "salt must be exactly 64 hex characters; got {:?} (length {})",
                options.salt,
                options.salt.len()
            ),
        });
    }
    if options.algorithm.is_empty() {
        return Err(OciUnpackError::VeritysetupFailed {
            reason: "algorithm must be a non-empty algorithm name (e.g. \"sha256\")".to_string(),
        });
    }
    if !options.data_block_size.is_power_of_two() {
        return Err(OciUnpackError::VeritysetupFailed {
            reason: format!(
                "data_block_size {} must be a power of two",
                options.data_block_size
            ),
        });
    }
    if !options.hash_block_size.is_power_of_two() {
        return Err(OciUnpackError::VeritysetupFailed {
            reason: format!(
                "hash_block_size {} must be a power of two",
                options.hash_block_size
            ),
        });
    }
    Ok(())
}

fn derive_output_paths(rootfs: &Path) -> (PathBuf, PathBuf) {
    // We name the sidecar / roothash files by stem so any rootfs
    // path works. `<dir>/rootfs.ext4` → `<dir>/rootfs.verity` +
    // `<dir>/rootfs.roothash`, matching the names the existing
    // Nix-built path produces (`nix/flake.nix`'s
    // `verityArtifacts`).
    let stem = rootfs
        .file_stem()
        .map(|s| s.to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("rootfs"));
    let parent = rootfs.parent().unwrap_or_else(|| Path::new(""));
    let mut sidecar = parent.join(&stem);
    sidecar.set_extension("verity");
    let mut roothash = parent.join(&stem);
    roothash.set_extension("roothash");
    (sidecar, roothash)
}

#[cfg(target_os = "linux")]
fn prepare_sidecar(sidecar: &Path) -> Result<(), OciUnpackError> {
    if let Some(parent) = sidecar.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // veritysetup format expects to write to an existing,
    // possibly-empty file. Truncate or create.
    let _ = std::fs::File::create(sidecar)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_veritysetup_format(
    rootfs: &Path,
    sidecar: &Path,
    options: &VeritysetupOptions,
) -> Result<String, OciUnpackError> {
    let binary: &Path = options
        .veritysetup_binary
        .as_deref()
        .unwrap_or_else(|| Path::new("veritysetup"));
    let mut cmd = std::process::Command::new(binary);
    cmd.arg("format")
        .arg(format!("--data-block-size={}", options.data_block_size))
        .arg(format!("--hash-block-size={}", options.hash_block_size))
        .arg(format!("--salt={}", options.salt))
        .arg(format!("--hash={}", options.algorithm))
        .arg(format!("--uuid={}", options.uuid))
        .arg(rootfs)
        .arg(sidecar);
    let exec = cmd
        .output()
        .map_err(|e| OciUnpackError::VeritysetupFailed {
            reason: format!("spawn `{}`: {e}", binary.display()),
        })?;
    if !exec.status.success() {
        let stderr = String::from_utf8_lossy(&exec.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&exec.stdout).into_owned();
        return Err(OciUnpackError::VeritysetupFailed {
            reason: format!(
                "exit {:?}; stderr={stderr}; stdout={stdout}",
                exec.status.code()
            ),
        });
    }
    let stdout = String::from_utf8_lossy(&exec.stdout);
    parse_root_hash(&stdout).ok_or_else(|| OciUnpackError::VeritysetupFailed {
        reason: format!(
            "veritysetup format succeeded but produced no `Root hash:` line; stdout={}",
            stdout.trim()
        ),
    })
}

/// Extract the root hash from `veritysetup format` stdout. The
/// output is a block of "key:value" lines; we look for the
/// `Root hash:` line and return its trimmed hex value (lowercase).
///
/// Compiled on every host so the unit tests can exercise it
/// without `veritysetup` installed; on non-Linux production
/// builds the function is unreachable, which clippy flags
/// without the `cfg_attr` below.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_root_hash(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        // Be permissive about case (`Root hash` vs `Roothash`)
        // and surrounding whitespace; veritysetup's output
        // format has been stable but a future version might
        // shift formatting.
        let lower = line.to_lowercase();
        if lower.starts_with("root hash:") || lower.starts_with("roothash:") {
            let (_, value) = line.split_once(':')?;
            // Hash values from veritysetup are hex; lowercase
            // them for consistency.
            return Some(value.trim().to_lowercase());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn write_roothash_file(path: &Path, roothash: &str) -> Result<(), OciUnpackError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut content = roothash.to_string();
    content.push('\n');
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "linux"))]
    use tempfile::TempDir;

    fn defaults() -> VeritysetupOptions {
        VeritysetupOptions::default()
    }

    #[test]
    fn defaults_match_mvm_verity_init_constants() {
        let o = defaults();
        assert_eq!(o.data_block_size, 1024);
        assert_eq!(o.hash_block_size, 4096);
        assert_eq!(o.salt, MVM_VERITY_PINNED_SALT);
        assert_eq!(o.algorithm, "sha256");
        assert_eq!(o.uuid, MVM_VERITY_PINNED_UUID);
        // The constants themselves are the contract; restate
        // them so any future drift fires this test before the
        // kernel panics at boot.
        assert_eq!(MVM_VERITY_DATA_BLOCK_SIZE, 1024);
        assert_eq!(MVM_VERITY_HASH_BLOCK_SIZE, 4096);
        assert_eq!(MVM_VERITY_PINNED_SALT.len(), 64);
        assert!(MVM_VERITY_PINNED_SALT.bytes().all(|b| b == b'0'));
        assert_eq!(MVM_VERITY_HASH_ALGORITHM, "sha256");
        assert_eq!(MVM_VERITY_PINNED_UUID.len(), 36);
    }

    #[test]
    fn derive_output_paths_uses_rootfs_stem() {
        let (sidecar, roothash) = derive_output_paths(Path::new("/tmp/foo/rootfs.ext4"));
        assert_eq!(sidecar, PathBuf::from("/tmp/foo/rootfs.verity"));
        assert_eq!(roothash, PathBuf::from("/tmp/foo/rootfs.roothash"));
    }

    #[test]
    fn derive_output_paths_handles_no_extension() {
        let (sidecar, roothash) = derive_output_paths(Path::new("/tmp/foo/myimage"));
        assert_eq!(sidecar, PathBuf::from("/tmp/foo/myimage.verity"));
        assert_eq!(roothash, PathBuf::from("/tmp/foo/myimage.roothash"));
    }

    #[test]
    fn derive_output_paths_handles_alternate_extension() {
        let (sidecar, roothash) = derive_output_paths(Path::new("/tmp/foo/myimage.img"));
        assert_eq!(sidecar, PathBuf::from("/tmp/foo/myimage.verity"));
        assert_eq!(roothash, PathBuf::from("/tmp/foo/myimage.roothash"));
    }

    #[test]
    fn validate_rejects_wrong_length_salt() {
        let opts = VeritysetupOptions {
            salt: "00".to_string(),
            ..defaults()
        };
        let err = validate_options(&opts).unwrap_err();
        assert!(matches!(err, OciUnpackError::VeritysetupFailed { .. }));
    }

    #[test]
    fn validate_rejects_non_hex_salt() {
        let opts = VeritysetupOptions {
            salt: "z".repeat(64),
            ..defaults()
        };
        let err = validate_options(&opts).unwrap_err();
        assert!(matches!(err, OciUnpackError::VeritysetupFailed { .. }));
    }

    #[test]
    fn validate_rejects_non_power_of_two_data_block() {
        let opts = VeritysetupOptions {
            data_block_size: 1000,
            ..defaults()
        };
        let err = validate_options(&opts).unwrap_err();
        assert!(matches!(err, OciUnpackError::VeritysetupFailed { .. }));
    }

    #[test]
    fn validate_rejects_empty_algorithm() {
        let opts = VeritysetupOptions {
            algorithm: String::new(),
            ..defaults()
        };
        let err = validate_options(&opts).unwrap_err();
        assert!(matches!(err, OciUnpackError::VeritysetupFailed { .. }));
    }

    #[test]
    fn parse_root_hash_finds_line_with_canonical_format() {
        let stdout = "VERITY header information for /tmp/rootfs.verity\n\
                      UUID:            abc\n\
                      Hash type:       1\n\
                      Data blocks:     1024\n\
                      Data block size: 1024\n\
                      Hash block size: 4096\n\
                      Hash algorithm:  sha256\n\
                      Salt:            0000000000000000\n\
                      Root hash:       ABC123def456\n";
        assert_eq!(parse_root_hash(stdout), Some("abc123def456".to_string()));
    }

    #[test]
    fn parse_root_hash_handles_lowercase_input() {
        let stdout = "Root hash: 0123456789abcdef\n";
        assert_eq!(
            parse_root_hash(stdout),
            Some("0123456789abcdef".to_string())
        );
    }

    #[test]
    fn parse_root_hash_returns_none_when_absent() {
        let stdout = "VERITY header information\nUUID: x\nNo hash here.\n";
        assert_eq!(parse_root_hash(stdout), None);
    }

    #[test]
    fn parse_root_hash_returns_none_on_empty_input() {
        assert_eq!(parse_root_hash(""), None);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seal_returns_host_unsupported_on_non_linux() {
        let tmp = TempDir::new().unwrap();
        let rootfs_path = tmp.path().join("rootfs.ext4");
        std::fs::write(&rootfs_path, b"unused").unwrap();
        let rootfs = MaterializedRootfs {
            path: rootfs_path,
            size_bytes: 0,
            label: "mvm-rootfs".to_string(),
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
        };
        let err = seal_with_verity(&rootfs, &defaults()).unwrap_err();
        match err {
            OciUnpackError::HostUnsupported { operation, .. } => {
                assert!(operation.contains("verity"), "got {operation:?}");
            }
            other => panic!("expected HostUnsupported, got {other:?}"),
        }
    }
}
