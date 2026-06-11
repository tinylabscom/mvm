//! Core unpack loop: tar entries → staging directory.
//!
//! Every public entry point in this module is hostile-input safe.
//! That property is load-bearing — each known attack class is gated
//! by checks that run BEFORE `std::fs` touches the host.

use crate::oci_to_rootfs::error::OciUnpackError;
use crate::oci_to_rootfs::path_validation::{normalize_entry_path, validate_symlink_target};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::{Archive, Entry, EntryType};

/// Knobs for [`ImageStaging`]. Defaults match the per-layer cap
/// in `mvm-oci` (2 GiB) and a per-entry cap of 1 GiB — both
/// generous enough for legitimate base images, both small enough
/// that a decompression-bomb manifest fails fast.
#[derive(Debug, Clone)]
pub struct StagingOptions {
    /// Maximum size of a single regular-file entry.
    pub max_entry_size: u64,
    /// Maximum total size of all entries applied in a single
    /// `apply_layer` call.
    pub max_layer_size: u64,
}

impl Default for StagingOptions {
    fn default() -> Self {
        Self {
            max_entry_size: 1024 * 1024 * 1024,
            max_layer_size: 2 * 1024 * 1024 * 1024,
        }
    }
}

/// Per-layer accounting returned from [`ImageStaging::apply_layer`].
#[derive(Debug, Clone, Default)]
pub struct LayerStats {
    /// Total bytes written for regular-file entries.
    pub bytes_written: u64,
    /// Number of entries processed (regular files, directories,
    /// symlinks, hardlinks, whiteouts — every tar entry).
    pub entries_processed: u64,
    /// Number of whiteout markers honoured.
    pub whiteouts_applied: u64,
}

/// Stateful unpacker rooted at a staging directory. Apply layers
/// in order; finalize when done.
pub struct ImageStaging {
    root: PathBuf,
    options: StagingOptions,
}

impl ImageStaging {
    /// Create a new staging area rooted at `root`. The directory
    /// must exist and be empty; the caller is responsible for
    /// picking a location (typically a `tempfile::TempDir` for
    /// tests or `/var/lib/mvm/oci-staging/<digest>` inside the
    /// builder VM for production).
    pub fn new(root: &Path, options: StagingOptions) -> Result<Self, OciUnpackError> {
        if !root.is_dir() {
            return Err(OciUnpackError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("staging root {root:?} does not exist or is not a directory"),
            )));
        }
        Ok(Self {
            root: root.to_path_buf(),
            options,
        })
    }

    /// Apply one OCI layer's worth of decompressed tar bytes to
    /// the staging area. Whiteouts in this layer remove files
    /// previously applied by earlier `apply_layer` calls.
    pub fn apply_layer<R: Read>(&mut self, tar_bytes: R) -> Result<LayerStats, OciUnpackError> {
        let mut archive = Archive::new(tar_bytes);
        let mut stats = LayerStats::default();
        let mut bytes_in_layer: u64 = 0;

        for entry_result in archive.entries()? {
            let mut entry = entry_result?;
            stats.entries_processed += 1;

            let raw_path = entry.path()?.into_owned();
            let normalized = normalize_entry_path(&raw_path)?;

            // Whiteouts are processed via filename inspection on
            // the basename — they never write to staging.
            if let Some(whiteout) = parse_whiteout(&normalized)? {
                apply_whiteout(&self.root, whiteout)?;
                stats.whiteouts_applied += 1;
                continue;
            }

            let entry_size = entry.header().size().unwrap_or(0);
            if entry.header().entry_type().is_file() && entry_size > self.options.max_entry_size {
                return Err(OciUnpackError::EntryTooLarge {
                    entry_path: normalized,
                    size: entry_size,
                    cap: self.options.max_entry_size,
                });
            }
            // Pre-check the running layer total so we fail before
            // writing the over-cap entry to disk.
            let projected = bytes_in_layer.saturating_add(entry_size);
            if projected > self.options.max_layer_size {
                return Err(OciUnpackError::LayerTooLarge {
                    applied: projected,
                    cap: self.options.max_layer_size,
                });
            }

            match entry.header().entry_type() {
                EntryType::Regular | EntryType::Continuous => {
                    let written = self.write_regular(&normalized, &mut entry)?;
                    bytes_in_layer = bytes_in_layer.saturating_add(written);
                    stats.bytes_written = stats.bytes_written.saturating_add(written);
                }
                EntryType::Directory => {
                    self.create_directory(&normalized, mode_of(&entry))?;
                }
                EntryType::Symlink => {
                    let target = entry
                        .link_name()?
                        .ok_or_else(|| OciUnpackError::SymlinkEscape {
                            link_path: normalized.clone(),
                            target: PathBuf::new(),
                        })?
                        .into_owned();
                    validate_symlink_target(&normalized, &target)?;
                    self.create_symlink(&normalized, &target)?;
                }
                EntryType::Link => {
                    let target = entry
                        .link_name()?
                        .ok_or_else(|| OciUnpackError::HardlinkInvalid {
                            link_path: normalized.clone(),
                            target: PathBuf::new(),
                            reason: "hardlink with no target",
                        })?
                        .into_owned();
                    let target_in_staging = normalize_entry_path(&target)?;
                    self.create_hardlink(&normalized, &target_in_staging)?;
                }
                other => {
                    return Err(OciUnpackError::UnsupportedEntryType {
                        entry_path: normalized,
                        entry_type: classify_entry_type(other),
                    });
                }
            }
        }

        Ok(stats)
    }

    /// Consume the staging area and return a [`StagedRootfs`]
    /// pointing at the populated directory. The staging directory
    /// is *not* deleted — that's the caller's responsibility (in
    /// production it's handed to `mke2fs -d`).
    pub fn finalize(self) -> Result<StagedRootfs, OciUnpackError> {
        Ok(StagedRootfs { root: self.root })
    }

    fn write_regular<R: Read>(
        &self,
        normalized: &Path,
        entry: &mut Entry<'_, R>,
    ) -> Result<u64, OciUnpackError> {
        let dest = self.root.join(normalized);
        // Ensure containing directory exists with permissive
        // default. Real perms are set when the directory's own
        // entry is processed (tar archives normally include
        // explicit directory entries).
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::File::create(&dest)?;
        let copied = std::io::copy(entry, &mut file)?;
        let perms = std::fs::Permissions::from_mode(mode_of(entry));
        std::fs::set_permissions(&dest, perms)?;
        Ok(copied)
    }

    fn create_directory(&self, normalized: &Path, mode: u32) -> Result<(), OciUnpackError> {
        let dest = self.root.join(normalized);
        std::fs::create_dir_all(&dest)?;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(&dest, perms)?;
        Ok(())
    }

    fn create_symlink(&self, normalized: &Path, target: &Path) -> Result<(), OciUnpackError> {
        let dest = self.root.join(normalized);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Remove any pre-existing entry at the destination. Later
        // OCI layers can overwrite earlier ones; whiteouts also
        // legitimately produce this pattern.
        let _ = std::fs::remove_file(&dest);
        std::os::unix::fs::symlink(target, &dest)?;
        Ok(())
    }

    fn create_hardlink(
        &self,
        normalized: &Path,
        target_in_staging: &Path,
    ) -> Result<(), OciUnpackError> {
        let dest = self.root.join(normalized);
        let target_abs = self.root.join(target_in_staging);
        // The target must actually exist in staging — a hardlink
        // entry that references a non-existent file is either
        // malformed or trying to interact with the host fs.
        if !target_abs.exists() {
            return Err(OciUnpackError::HardlinkInvalid {
                link_path: normalized.to_path_buf(),
                target: target_in_staging.to_path_buf(),
                reason: "hardlink target does not exist in staging",
            });
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = std::fs::remove_file(&dest);
        std::fs::hard_link(&target_abs, &dest)?;
        Ok(())
    }
}

/// Final descriptor after `finalize`. Just the path today; an ext4
/// sidecar generated by `mke2fs -d` will be added later.
#[derive(Debug, Clone)]
pub struct StagedRootfs {
    pub root: PathBuf,
}

/// Pull a file mode from the tar entry header; default to 0644
/// for files and 0755 for directories when the header lacks one.
fn mode_of<R: Read>(entry: &Entry<'_, R>) -> u32 {
    let header_mode = entry.header().mode().unwrap_or(0);
    if header_mode != 0 {
        header_mode
    } else if entry.header().entry_type() == EntryType::Directory {
        0o755
    } else {
        0o644
    }
}

fn classify_entry_type(et: EntryType) -> &'static str {
    match et {
        EntryType::Block => "block-device",
        EntryType::Char => "character-device",
        EntryType::Fifo => "fifo",
        EntryType::GNUSparse => "gnu-sparse",
        EntryType::XGlobalHeader => "pax-global-header",
        EntryType::XHeader => "pax-extended-header",
        _ => "other",
    }
}

/// Whiteout marker parsed from a normalized entry path.
#[derive(Debug)]
enum Whiteout {
    /// `<dir>/.wh.<name>` — remove `<dir>/<name>` from staging.
    Single { dir: PathBuf, name: String },
    /// `<dir>/.wh..wh..opq` — clear `<dir>/`'s contents in
    /// staging (any files previous layers added).
    Opaque { dir: PathBuf },
}

const WHITEOUT_PREFIX: &str = ".wh.";
const OPAQUE_MARKER: &str = ".wh..wh..opq";

fn parse_whiteout(normalized: &Path) -> Result<Option<Whiteout>, OciUnpackError> {
    let basename = normalized
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if basename == OPAQUE_MARKER {
        let dir = normalized.parent().unwrap_or(Path::new("")).to_path_buf();
        return Ok(Some(Whiteout::Opaque { dir }));
    }
    if let Some(stripped) = basename.strip_prefix(WHITEOUT_PREFIX) {
        if stripped.is_empty() {
            return Err(OciUnpackError::InvalidWhiteout {
                entry_path: normalized.to_path_buf(),
                reason: "whiteout marker has empty target name",
            });
        }
        if stripped.contains('/') || stripped == "." || stripped == ".." {
            return Err(OciUnpackError::InvalidWhiteout {
                entry_path: normalized.to_path_buf(),
                reason: "whiteout target name must be a plain filename",
            });
        }
        let dir = normalized.parent().unwrap_or(Path::new("")).to_path_buf();
        return Ok(Some(Whiteout::Single {
            dir,
            name: stripped.to_string(),
        }));
    }
    Ok(None)
}

fn apply_whiteout(root: &Path, whiteout: Whiteout) -> Result<(), OciUnpackError> {
    match whiteout {
        Whiteout::Single { dir, name } => {
            let target = root.join(&dir).join(&name);
            remove_path(&target)?;
        }
        Whiteout::Opaque { dir } => {
            let target_dir = root.join(&dir);
            if target_dir.is_dir() {
                // Reset the directory's contents but leave the
                // directory itself. Subsequent entries in this
                // same layer will re-populate it.
                for entry in std::fs::read_dir(&target_dir)? {
                    let entry = entry?;
                    remove_path(&entry.path())?;
                }
            }
        }
    }
    Ok(())
}

fn remove_path(p: &Path) -> Result<(), OciUnpackError> {
    if !p.exists() && std::fs::symlink_metadata(p).is_err() {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(p)?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(p)?;
    } else {
        std::fs::remove_file(p)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whiteout_parses_single_form() {
        let w = parse_whiteout(Path::new("etc/.wh.passwd"))
            .unwrap()
            .unwrap();
        match w {
            Whiteout::Single { dir, name } => {
                assert_eq!(dir, PathBuf::from("etc"));
                assert_eq!(name, "passwd");
            }
            _ => panic!("expected single whiteout"),
        }
    }

    #[test]
    fn whiteout_parses_opaque_form() {
        let w = parse_whiteout(Path::new("usr/lib/.wh..wh..opq"))
            .unwrap()
            .unwrap();
        match w {
            Whiteout::Opaque { dir } => {
                assert_eq!(dir, PathBuf::from("usr/lib"));
            }
            _ => panic!("expected opaque whiteout"),
        }
    }

    #[test]
    fn whiteout_rejects_empty_target_name() {
        // `.wh.` alone has no target.
        let err = parse_whiteout(Path::new("etc/.wh.")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::InvalidWhiteout { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn whiteout_rejects_dot_target() {
        let err = parse_whiteout(Path::new("etc/.wh..")).unwrap_err();
        assert!(
            matches!(err, OciUnpackError::InvalidWhiteout { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn non_whiteout_returns_none() {
        assert!(parse_whiteout(Path::new("etc/passwd")).unwrap().is_none());
        assert!(
            parse_whiteout(Path::new("usr/lib/file.wh.tar"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn classify_entry_type_covers_unsupported_classes() {
        // Just ensure each branch produces a non-empty string;
        // the exact wording is documentation.
        for et in [
            EntryType::Block,
            EntryType::Char,
            EntryType::Fifo,
            EntryType::GNUSparse,
        ] {
            let s = classify_entry_type(et);
            assert!(!s.is_empty(), "{et:?}");
        }
    }
}
