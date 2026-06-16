//! ext4 materialization from a staged rootfs.
//!
//! After [`crate::oci_to_rootfs::ImageStaging::apply_layer`] has
//! populated a staging directory, this module produces the
//! `rootfs.ext4` image that Firecracker / libkrun / Apple
//! Container load as the guest's root device. Output is **byte-
//! deterministic** for a given staged tree + options — this is
//! load-bearing for the pull-time verity story: the verity
//! sidecar generated next would otherwise differ across runs and
//! defeat the per-digest verity cache.
//!
//! Determinism comes from pinning everything `mke2fs` randomizes
//! by default:
//!
//! - `-U <uuid>` — filesystem UUID.
//! - `-E hash_seed=<uuid>` — htree directory-hash seed (controls
//!   dirent ordering inside a directory).
//! - `SOURCE_DATE_EPOCH=0` env — every file's mtime is pinned to
//!   the Unix epoch.
//! - `-E no_copy_xattrs` — xattrs are skipped uniformly (we don't
//!   forward OCI xattrs through unpack today anyway).
//! - `-b 4096` — fixed block size.
//! - `-t ext4` — fixed FS type.
//! - `-O ^orphan_file` — disable the orphan-file feature (default-on in
//!   e2fsprogs >= 1.47); its inode bytes vary run-to-run.
//!
//! ## Host support
//!
//! `mke2fs` is Linux-only. On Linux, [`materialize_to_ext4`]
//! shells out directly. On macOS / Windows the same function
//! returns [`OciUnpackError::HostUnsupported`]; the CLI
//! orchestrator routes the call through the libkrun builder VM.
//! This module's job is to be the in-process orchestrator; the
//! host-vs-VM routing decision lives one layer up.

use crate::oci_to_rootfs::error::OciUnpackError;
use crate::oci_to_rootfs::unpack::StagedRootfs;
use std::path::{Path, PathBuf};

/// Knobs for [`materialize_to_ext4`]. Defaults produce a
/// byte-deterministic image suitable for verity
/// generation; callers can override any field to e.g. label the
/// filesystem differently for a non-mvm consumer.
#[derive(Debug, Clone)]
pub struct Mke2fsOptions {
    /// `-L` label written into the superblock. 16-byte max
    /// (ext4 limit); longer values are truncated by `mke2fs`.
    pub label: String,
    /// `-U` filesystem UUID. Default
    /// `00000000-0000-0000-0000-000000000001` — pinned for
    /// determinism. Override via `with_random_uuid` if a
    /// caller specifically wants a fresh UUID.
    pub uuid: String,
    /// Hash seed for htree dirent ordering. Default
    /// `00000000-0000-0000-0000-000000000002`. The seed must
    /// stay pinned across runs for verity-cache hits.
    pub hash_seed: String,
    /// Block size in bytes. Default 4096 — what the kernel
    /// expects for a verity-protected root, and what mvm's
    /// existing `verityArtifacts` Nix derivation uses.
    pub block_size: u32,
    /// Extra bytes added on top of [`estimate_image_size`]'s
    /// computed minimum, to account for `mke2fs`'s metadata
    /// overhead and any post-format writes. Default 4 MiB; an
    /// undersized image yields a hard `mke2fs` failure rather
    /// than truncated content, so the padding is for ergonomics,
    /// not correctness.
    pub size_padding_bytes: u64,
    /// `SOURCE_DATE_EPOCH` env value passed to `mke2fs`. Default
    /// 0 — every file timestamp becomes the Unix epoch. The verity
    /// story needs this so two runs of the same source tree
    /// produce byte-identical ext4.
    pub source_date_epoch: u64,
    /// Override the `mke2fs` binary location. Default `None` —
    /// the binary is resolved via `$PATH`. Tests use this to
    /// substitute a stub.
    pub mke2fs_binary: Option<PathBuf>,
}

impl Default for Mke2fsOptions {
    fn default() -> Self {
        Self {
            label: "mvm-rootfs".to_string(),
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            hash_seed: "00000000-0000-0000-0000-000000000002".to_string(),
            block_size: 4096,
            size_padding_bytes: 4 * 1024 * 1024,
            source_date_epoch: 0,
            mke2fs_binary: None,
        }
    }
}

/// Final descriptor produced by [`materialize_to_ext4`].
#[derive(Debug, Clone)]
pub struct MaterializedRootfs {
    /// Absolute path to the ext4 image file on the host fs.
    pub path: PathBuf,
    /// File size in bytes, exactly what was passed to
    /// `mke2fs` via the preallocated output file.
    pub size_bytes: u64,
    /// Label written into the superblock (matches `options.label`).
    pub label: String,
    /// Filesystem UUID written into the superblock.
    pub uuid: String,
}

/// Compute the minimum ext4 image size for the staged tree.
/// Walks every entry under `staged_root` to sum regular-file
/// bytes, then adds a small per-entry overhead (~256 bytes for
/// the inode + dirent) plus the options-supplied padding,
/// rounded up to a multiple of `block_size`. The minimum result
/// is always at least 1 MiB — `mke2fs` rejects smaller images
/// outright.
pub fn estimate_image_size(
    staged_root: &Path,
    options: &Mke2fsOptions,
) -> Result<u64, OciUnpackError> {
    let (total_file_bytes, entries) = walk_size(staged_root)?;
    // Per-entry overhead covers inode + directory entry + a bit
    // of slack for bitmap/group-descriptor growth. 1024 bytes per
    // entry is conservative — typical ext4 needs ~256, but
    // small-files workloads can exceed that.
    let entry_overhead = entries.saturating_mul(1024);
    // Group-descriptor + superblock + reserved-blocks overhead
    // grows with image size. ~1.5% is a generous floor.
    let metadata_overhead = total_file_bytes / 64;
    let raw = total_file_bytes
        .saturating_add(entry_overhead)
        .saturating_add(metadata_overhead)
        .saturating_add(options.size_padding_bytes);
    let block = options.block_size.max(512) as u64;
    let rounded = raw.div_ceil(block).saturating_mul(block);
    Ok(rounded.max(1024 * 1024))
}

/// Produce an ext4 image file at `output` from the contents of
/// `staged.root`, with deterministic on-disk bytes for a given
/// (staged tree, options) pair.
///
/// Linux-only at runtime; non-Linux hosts return
/// [`OciUnpackError::HostUnsupported`]. The CLI orchestrator
/// routes the macOS path through the libkrun builder VM — that
/// routing lives one layer up, not in this module.
pub fn materialize_to_ext4(
    staged: &StagedRootfs,
    output: &Path,
    options: &Mke2fsOptions,
) -> Result<MaterializedRootfs, OciUnpackError> {
    let size_bytes = estimate_image_size(&staged.root, options)?;

    #[cfg(target_os = "linux")]
    {
        prepare_output_file(output, size_bytes)?;
        run_mke2fs(&staged.root, output, options)?;
        Ok(MaterializedRootfs {
            path: output.to_path_buf(),
            size_bytes,
            label: options.label.clone(),
            uuid: options.uuid.clone(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Touch the variables to silence unused-variable warnings
        // while keeping the same function signature across hosts.
        let _ = (output, size_bytes);
        Err(OciUnpackError::HostUnsupported {
            operation: "ext4 image materialization (mke2fs)",
            reason: "mke2fs is Linux-only; the W1.5 CLI orchestrator routes this through the libkrun builder VM (ADR-050)",
        })
    }
}

#[cfg(target_os = "linux")]
fn prepare_output_file(output: &Path, size_bytes: u64) -> Result<(), OciUnpackError> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::File::create(output)?;
    file.set_len(size_bytes)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_mke2fs(
    staged_root: &Path,
    output: &Path,
    options: &Mke2fsOptions,
) -> Result<(), OciUnpackError> {
    let binary: &Path = options
        .mke2fs_binary
        .as_deref()
        .unwrap_or_else(|| Path::new("mke2fs"));
    // mke2fs's `-E` is last-wins, not accumulating — passing it twice
    // silently drops the earlier value. Combine extended options into a
    // single comma-separated `-E` so `hash_seed` actually takes effect
    // (without this, mke2fs picks a fresh random hash seed each call,
    // shifting the htree layout and breaking the byte-determinism the
    // verity cache depends on).
    let mut cmd = std::process::Command::new(binary);
    cmd.env("SOURCE_DATE_EPOCH", options.source_date_epoch.to_string())
        .args(["-F"]) // overwrite the preallocated output file
        .args(["-t", "ext4"])
        // Disable `orphan_file`: e2fsprogs >= 1.47 enables it by default,
        // and it allocates an orphan-file inode whose on-disk bytes vary
        // between otherwise-identical runs — defeating the verity
        // cache's byte-determinism (and `^metadata_csum_seed` is moot
        // because `-U` already pins the seed). It's only a crash-recovery
        // optimization, irrelevant for a read-only verity rootfs.
        .args(["-O", "^orphan_file"])
        .args(["-L", &options.label])
        .args(["-U", &options.uuid])
        .args([
            "-E",
            &format!("hash_seed={},no_copy_xattrs", options.hash_seed),
        ])
        .args(["-b", &options.block_size.to_string()])
        .arg("-d")
        .arg(staged_root)
        .arg(output);
    let exec = cmd.output().map_err(|e| OciUnpackError::Mke2fsFailed {
        reason: format!("spawn `{}`: {e}", binary.display()),
    })?;
    if !exec.status.success() {
        let stderr = String::from_utf8_lossy(&exec.stderr).into_owned();
        let stdout = String::from_utf8_lossy(&exec.stdout).into_owned();
        return Err(OciUnpackError::Mke2fsFailed {
            reason: format!(
                "exit {:?}; stderr={stderr}; stdout={stdout}",
                exec.status.code()
            ),
        });
    }
    Ok(())
}

/// Recursive directory walk that returns
/// `(total_file_bytes, total_entry_count)`. Counts every entry
/// type (regular files, directories, symlinks). Symlinks count
/// once toward `entries` and contribute their *link target
/// string length* toward `bytes`, which is what ext4 actually
/// stores for fast-symlinks under 60 bytes (longer ones spill
/// into a block; the overestimate is fine).
fn walk_size(root: &Path) -> Result<(u64, u64), OciUnpackError> {
    fn visit(dir: &Path, bytes: &mut u64, entries: &mut u64) -> Result<(), OciUnpackError> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            *entries = entries.saturating_add(1);
            let metadata = entry.metadata()?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                visit(&entry.path(), bytes, entries)?;
            } else if metadata.is_file() {
                *bytes = bytes.saturating_add(metadata.len());
            } else if metadata.file_type().is_symlink() {
                let link_target = std::fs::read_link(entry.path())?;
                let len = link_target.as_os_str().as_encoded_bytes().len() as u64;
                *bytes = bytes.saturating_add(len);
            }
        }
        Ok(())
    }

    let mut bytes: u64 = 0;
    let mut entries: u64 = 0;
    if root.is_dir() {
        visit(root, &mut bytes, &mut entries)?;
    }
    Ok((bytes, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn defaults() -> Mke2fsOptions {
        Mke2fsOptions::default()
    }

    #[test]
    fn defaults_are_deterministic_and_pinned() {
        let o = defaults();
        assert_eq!(o.label, "mvm-rootfs");
        assert_eq!(o.uuid, "00000000-0000-0000-0000-000000000001");
        assert_eq!(o.hash_seed, "00000000-0000-0000-0000-000000000002");
        assert_eq!(o.block_size, 4096);
        assert_eq!(o.source_date_epoch, 0);
        // Padding is large enough to absorb mke2fs overhead but
        // not so large that small images pay an outsized cost.
        assert_eq!(o.size_padding_bytes, 4 * 1024 * 1024);
    }

    #[test]
    fn empty_staging_estimate_is_dominated_by_padding() {
        let tmp = TempDir::new().unwrap();
        let est = estimate_image_size(tmp.path(), &defaults()).unwrap();
        // Empty staging contributes zero raw bytes, so the
        // estimate equals the padding (rounded up to block
        // size). Default padding is 4 MiB which is already
        // block-aligned, so the result is exactly that.
        assert_eq!(est, 4 * 1024 * 1024);
    }

    #[test]
    fn empty_staging_with_zero_padding_clamps_to_1_mib_floor() {
        let tmp = TempDir::new().unwrap();
        let opts = Mke2fsOptions {
            size_padding_bytes: 0,
            ..defaults()
        };
        let est = estimate_image_size(tmp.path(), &opts).unwrap();
        // Below 1 MiB the clamp kicks in. mke2fs would reject a
        // smaller image; the floor protects against that.
        assert_eq!(est, 1024 * 1024);
    }

    #[test]
    fn estimate_rounds_up_to_block_boundary() {
        let tmp = TempDir::new().unwrap();
        // Write a single 17-byte file. With the 4 MiB padding +
        // per-entry overhead, the rounded result must be a
        // multiple of the 4096-byte block size.
        fs::write(tmp.path().join("payload"), b"seventeen-bytes!!").unwrap();
        let est = estimate_image_size(tmp.path(), &defaults()).unwrap();
        assert_eq!(est % 4096, 0, "{est} should be a multiple of 4096");
    }

    #[test]
    fn estimate_includes_padding_above_raw_file_bytes() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("payload"), vec![0u8; 1000]).unwrap();
        let est = estimate_image_size(tmp.path(), &defaults()).unwrap();
        // Default padding alone is 4 MiB, plus entry overhead
        // adds another 1 KiB. The estimate must be comfortably
        // above the raw 1000-byte file.
        assert!(
            est > 4 * 1024 * 1024,
            "estimate {est} should exceed padding floor"
        );
    }

    #[test]
    fn estimate_grows_with_file_count() {
        let tmp_few = TempDir::new().unwrap();
        for i in 0..5 {
            fs::write(tmp_few.path().join(format!("f{i}")), b"x").unwrap();
        }
        let est_few = estimate_image_size(tmp_few.path(), &defaults()).unwrap();

        let tmp_many = TempDir::new().unwrap();
        for i in 0..5000 {
            fs::write(tmp_many.path().join(format!("f{i}")), b"x").unwrap();
        }
        let est_many = estimate_image_size(tmp_many.path(), &defaults()).unwrap();
        assert!(
            est_many > est_few,
            "estimate for 5000 entries ({est_many}) should exceed estimate for 5 ({est_few})"
        );
    }

    #[test]
    fn estimate_handles_nested_directories() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("a/b/c")).unwrap();
        fs::write(tmp.path().join("a/b/c/leaf"), b"leaf-bytes").unwrap();
        let est = estimate_image_size(tmp.path(), &defaults()).unwrap();
        assert!(est >= 1024 * 1024);
    }

    #[test]
    fn estimate_handles_symlinks_without_following_them() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("real"), b"real-bytes").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("real", tmp.path().join("link")).unwrap();
        let est = estimate_image_size(tmp.path(), &defaults()).unwrap();
        assert!(est >= 1024 * 1024);
        // The symlink counts as one entry but doesn't double-count
        // the target's bytes (we read the link target string,
        // not the file behind it).
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn materialize_returns_host_unsupported_on_non_linux() {
        let tmp = TempDir::new().unwrap();
        let staged = StagedRootfs {
            root: tmp.path().to_path_buf(),
        };
        let output = tmp.path().join("rootfs.ext4");
        let err = materialize_to_ext4(&staged, &output, &defaults()).unwrap_err();
        match err {
            OciUnpackError::HostUnsupported { operation, .. } => {
                assert!(
                    operation.contains("ext4"),
                    "operation message should name ext4: got {operation:?}"
                );
            }
            other => panic!("expected HostUnsupported, got {other:?}"),
        }
    }
}
