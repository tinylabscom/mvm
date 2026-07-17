//! ext4 materialization from a staged rootfs.
//!
//! After [`crate::oci_to_rootfs::ImageStaging::apply_layer`] has populated a
//! staging directory, this module produces the `rootfs.ext4` image that
//! Firecracker / libkrun / Apple Container load as the guest's root device.
//! Output is **byte-deterministic** for a given staged tree + options — this
//! is load-bearing for the pull-time verity story: the verity sidecar
//! generated next would otherwise differ across runs and defeat the per-digest
//! verity cache.
//!
//! The default path now uses the in-process `mvm-ext4` writer, which is
//! deterministic by construction and avoids `mke2fs` timestamp drift on newer
//! e2fsprogs releases. Option combinations the pure writer does not model yet
//! still fall back to `mke2fs` on Linux, keeping the existing escape hatch for
//! non-default formatting requests.
//!
//! ## Host support
//!
//! The public behavior stays Linux-only for now. On Linux,
//! [`materialize_to_ext4`] uses the in-process writer for the default,
//! deterministic profile and falls back to `mke2fs` for unsupported option
//! combinations. On macOS / Windows the same function returns
//! [`OciUnpackError::HostUnsupported`]; the CLI orchestrator routes the call
//! through the libkrun builder VM. This module's job is to be the in-process
//! orchestrator; the host-vs-VM routing decision lives one layer up.

use crate::oci_to_rootfs::error::OciUnpackError;
use crate::oci_to_rootfs::unpack::StagedRootfs;
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", test))]
const DISABLED_EXT4_FEATURES: &str = "^has_journal,^orphan_file";

#[cfg(any(target_os = "linux", test))]
const SOURCE_DATE_EPOCH_ENV: &str = "SOURCE_DATE_EPOCH";

#[cfg(any(target_os = "linux", test))]
const E2FSPROGS_FAKE_TIME_ENV: &str = "E2FSPROGS_FAKE_TIME";

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
    /// Deterministic timestamp value passed to `mke2fs`. Default
    /// 0 — filesystem creation/check times and e2fsprogs
    /// current-time fallbacks are pinned to the Unix epoch. The
    /// verity story needs this so two runs of the same source
    /// tree produce byte-identical ext4.
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
    /// File size in bytes.
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
    #[cfg(target_os = "linux")]
    {
        if let Some(build_options) = in_process_build_options(options) {
            return materialize_in_process(&staged.root, output, options, &build_options);
        }

        let size_bytes = estimate_image_size(&staged.root, options)?;
        prepare_output_file(output, size_bytes)?;
        run_mke2fs(&staged.root, output, options)?;
        Ok(materialized_rootfs(output, size_bytes, options))
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Touch the variables to silence unused-variable warnings
        // while keeping the same function signature across hosts.
        let _ = (staged, output, options);
        Err(OciUnpackError::HostUnsupported {
            operation: "ext4 image materialization (mke2fs)",
            reason: "mke2fs is Linux-only; the W1.5 CLI orchestrator routes this through the libkrun builder VM (ADR-017)",
        })
    }
}

#[cfg(target_os = "linux")]
fn materialized_rootfs(
    output: &Path,
    size_bytes: u64,
    options: &Mke2fsOptions,
) -> MaterializedRootfs {
    MaterializedRootfs {
        path: output.to_path_buf(),
        size_bytes,
        label: options.label.clone(),
        uuid: options.uuid.clone(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn in_process_build_options(options: &Mke2fsOptions) -> Option<crate::ext4::BuildOptions> {
    let defaults = Mke2fsOptions::default();
    if options.hash_seed != defaults.hash_seed
        || options.block_size != crate::ext4::BLOCK_SIZE
        || options.size_padding_bytes != defaults.size_padding_bytes
        || options.source_date_epoch != defaults.source_date_epoch
        || options.mke2fs_binary.is_some()
    {
        return None;
    }

    let uuid = uuid::Uuid::parse_str(&options.uuid).ok()?;
    Some(
        crate::ext4::BuildOptions::default()
            .with_uuid(*uuid.as_bytes())
            .with_volume_name(options.label.as_bytes()),
    )
}

#[cfg(target_os = "linux")]
fn materialize_in_process(
    staged_root: &Path,
    output: &Path,
    options: &Mke2fsOptions,
    build_options: &crate::ext4::BuildOptions,
) -> Result<MaterializedRootfs, OciUnpackError> {
    let nodes = collect_nodes(staged_root)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(output)?;
    let size_bytes =
        match crate::ext4::emit_image_with_options(&nodes, build_options, |offset, bytes| {
            file.seek(SeekFrom::Start(offset))
                .and_then(|_| file.write_all(bytes))
        }) {
            Ok(size_bytes) => size_bytes,
            Err(crate::ext4::EmitImageError::Build(err)) => {
                return Err(OciUnpackError::Mke2fsFailed {
                    reason: format!("in-process ext4 build failed: {err}"),
                });
            }
            Err(crate::ext4::EmitImageError::Emit(err)) => return Err(err.into()),
        };
    file.set_len(size_bytes)?;
    Ok(materialized_rootfs(output, size_bytes, options))
}

#[cfg(target_os = "linux")]
fn collect_nodes(root: &Path) -> Result<Vec<crate::ext4::Node>, OciUnpackError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let guest_path = guest_path_of(root, &path);
            let ft = entry.file_type()?;
            if ft.is_symlink() {
                let target = std::fs::read_link(&path)?;
                out.push(crate::ext4::Node::Symlink {
                    path: guest_path,
                    target: target.to_string_lossy().into_owned(),
                });
            } else if ft.is_dir() {
                out.push(crate::ext4::Node::Dir {
                    path: guest_path,
                    mode: mode_of(&path, 0o755),
                    xattrs: Vec::new(),
                });
                stack.push(path);
            } else if ft.is_file() {
                let data = std::fs::read(&path)?;
                out.push(crate::ext4::Node::File {
                    path: guest_path,
                    mode: mode_of(&path, 0o644),
                    data,
                    xattrs: Vec::new(),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn guest_path_of(root: &Path, path: &Path) -> String {
    match path.strip_prefix(root) {
        Ok(rel) => format!("/{}", rel.to_string_lossy()),
        Err(_) => format!("/{}", path.to_string_lossy()),
    }
}

#[cfg(target_os = "linux")]
fn mode_of(path: &Path, default: u16) -> u16 {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => (metadata.permissions().mode() & 0o7777) as u16,
        Err(_) => default,
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
    let binary = selected_mke2fs_binary(options);
    let mut cmd = build_mke2fs_command(binary, staged_root, output, options);
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

#[cfg(any(target_os = "linux", test))]
fn selected_mke2fs_binary(options: &Mke2fsOptions) -> &Path {
    options
        .mke2fs_binary
        .as_deref()
        .unwrap_or_else(|| Path::new("mke2fs"))
}

#[cfg(any(target_os = "linux", test))]
fn build_mke2fs_command(
    binary: &Path,
    staged_root: &Path,
    output: &Path,
    options: &Mke2fsOptions,
) -> std::process::Command {
    // mke2fs's `-E` is last-wins, not accumulating — passing it twice
    // silently drops the earlier value. Combine extended options into a
    // single comma-separated `-E` so `hash_seed` actually takes effect
    // (without this, mke2fs picks a fresh random hash seed each call,
    // shifting the htree layout and breaking the byte-determinism the
    // verity cache depends on).
    let mut cmd = std::process::Command::new(binary);
    let deterministic_time = options.source_date_epoch.to_string();
    cmd.env(SOURCE_DATE_EPOCH_ENV, &deterministic_time)
        .env(E2FSPROGS_FAKE_TIME_ENV, deterministic_time)
        .args(["-F"]) // overwrite the preallocated output file
        .args(["-t", "ext4"])
        // Disable features that can carry run-specific bytes. The journal and
        // orphan-file are crash-recovery machinery, irrelevant for a read-only
        // dm-verity rootfs, and they defeat byte-deterministic sealing on some
        // e2fsprogs versions.
        .args(["-O", DISABLED_EXT4_FEATURES])
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
    cmd
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
    #[cfg(target_os = "linux")]
    use std::process::Command;
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
    fn mke2fs_command_pins_all_time_sources() {
        let tmp = TempDir::new().unwrap();
        let output = tmp.path().join("rootfs.ext4");
        let options = Mke2fsOptions {
            source_date_epoch: 123,
            mke2fs_binary: Some(PathBuf::from("/usr/sbin/mke2fs")),
            ..defaults()
        };
        let cmd = build_mke2fs_command(
            selected_mke2fs_binary(&options),
            tmp.path(),
            &output,
            &options,
        );

        assert_eq!(
            command_env_value(&cmd, SOURCE_DATE_EPOCH_ENV).as_deref(),
            Some("123")
        );
        assert_eq!(
            command_env_value(&cmd, E2FSPROGS_FAKE_TIME_ENV).as_deref(),
            Some("123")
        );
    }

    fn command_env_value(cmd: &std::process::Command, key: &str) -> Option<String> {
        cmd.get_envs()
            .find(|(name, _)| *name == std::ffi::OsStr::new(key))
            .and_then(|(_, value)| value.map(|v| v.to_string_lossy().into_owned()))
    }

    #[test]
    fn mutable_ext4_features_are_disabled_for_determinism() {
        let disabled: Vec<&str> = DISABLED_EXT4_FEATURES.split(',').collect();
        assert!(
            disabled.contains(&"^has_journal"),
            "journal bytes are not stable enough for verity-cache determinism"
        );
        assert!(
            disabled.contains(&"^orphan_file"),
            "orphan-file bytes are not stable enough for verity-cache determinism"
        );
    }

    #[test]
    fn in_process_path_supports_default_options() {
        assert!(in_process_build_options(&defaults()).is_some());
    }

    #[test]
    fn in_process_path_rejects_non_default_block_size() {
        let options = Mke2fsOptions {
            block_size: 1024,
            ..defaults()
        };
        assert!(in_process_build_options(&options).is_none());
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

    #[cfg(target_os = "linux")]
    #[test]
    fn in_process_materialize_matches_dense_writer_bytes() {
        let staged_dir = TempDir::new().unwrap();
        fs::create_dir_all(staged_dir.path().join("etc")).unwrap();
        fs::write(
            staged_dir.path().join("etc/hosts"),
            b"127.0.0.1 localhost\n",
        )
        .unwrap();
        fs::write(
            staged_dir.path().join("hello"),
            b"hello from streamed ext4\n",
        )
        .unwrap();
        let staged = StagedRootfs {
            root: staged_dir.path().to_path_buf(),
        };
        let output_dir = TempDir::new().unwrap();
        let output = output_dir.path().join("rootfs.ext4");
        let options = defaults();
        let build_options = in_process_build_options(&options).expect("default options supported");
        let nodes = collect_nodes(&staged.root).expect("collect nodes");
        let dense =
            crate::ext4::build_image_with_options(&nodes, &build_options).expect("dense image");

        let materialized = materialize_in_process(&staged.root, &output, &options, &build_options)
            .expect("streamed in-process materialize");

        let streamed = fs::read(&output).expect("read streamed rootfs");
        assert_eq!(streamed, dense, "streamed bytes must match dense writer");
        assert_eq!(materialized.size_bytes, dense.len() as u64);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tools_validate_streamed_rootfs_and_reject_corruption() {
        if !tool_available("e2fsck") || !tool_available("debugfs") {
            eprintln!("skipping linux ext4 oracles: e2fsck/debugfs unavailable");
            return;
        }

        let staged_dir = TempDir::new().unwrap();
        fs::create_dir_all(staged_dir.path().join("etc")).unwrap();
        fs::write(
            staged_dir.path().join("etc/hosts"),
            b"127.0.0.1 localhost\n",
        )
        .unwrap();
        fs::write(staged_dir.path().join("hello"), b"oracle witness\n").unwrap();
        let output_dir = TempDir::new().unwrap();
        let output = output_dir.path().join("rootfs.ext4");
        let options = defaults();
        let build_options = in_process_build_options(&options).expect("default options supported");

        materialize_in_process(staged_dir.path(), &output, &options, &build_options)
            .expect("streamed in-process materialize");

        let fsck = Command::new("e2fsck")
            .args(["-fn", output.to_str().expect("utf-8 path")])
            .output()
            .expect("run e2fsck");
        assert!(
            fsck.status.success(),
            "e2fsck should accept the streamed image: {}",
            String::from_utf8_lossy(&fsck.stderr)
        );

        let listing = Command::new("debugfs")
            .args(["-R", "ls -l /etc", output.to_str().expect("utf-8 path")])
            .output()
            .expect("run debugfs ls");
        assert!(
            listing.status.success(),
            "debugfs ls should succeed: {}",
            String::from_utf8_lossy(&listing.stderr)
        );
        let listing_stdout = String::from_utf8_lossy(&listing.stdout);
        assert!(
            listing_stdout.contains("hosts"),
            "debugfs listing should mention /etc/hosts: {listing_stdout}"
        );

        let cat = Command::new("debugfs")
            .args(["-R", "cat /hello", output.to_str().expect("utf-8 path")])
            .output()
            .expect("run debugfs cat");
        assert!(cat.status.success(), "debugfs cat should succeed");
        assert_eq!(cat.stdout, b"oracle witness\n");

        let corrupt = output_dir.path().join("rootfs-corrupt.ext4");
        let mut bytes = fs::read(&output).expect("read good rootfs");
        bytes[1024 + 0x38] ^= 0xFF;
        fs::write(&corrupt, &bytes).expect("write corrupt rootfs");

        let corrupted_fsck = Command::new("e2fsck")
            .args(["-fn", corrupt.to_str().expect("utf-8 path")])
            .output()
            .expect("run e2fsck on corrupt image");
        assert!(
            !corrupted_fsck.status.success(),
            "e2fsck should reject the corrupted image"
        );
    }

    #[cfg(target_os = "linux")]
    fn tool_available(name: &str) -> bool {
        Command::new(name).arg("-V").output().is_ok()
    }
}
