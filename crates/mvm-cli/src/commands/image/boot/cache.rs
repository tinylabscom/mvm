//! What the boot-image cache currently holds, read off disk.
//!
//! One survey backs every `image boot` verb: `status` renders it, `check`
//! reads the tag out of it, and `update` replaces an entry in it. A second
//! reader would be free to disagree with the first about which bytes are live.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_build::builder_vm::GuestSidecar;

use crate::commands::env::builder_vm::default_microvm::DefaultMicrovmVariant;

/// Both variants, in the order they are reported.
pub(super) const VARIANTS: [DefaultMicrovmVariant; 2] =
    [DefaultMicrovmVariant::Dev, DefaultMicrovmVariant::Prod];

/// Root under which every variant directory lives.
pub(super) fn cache_root() -> PathBuf {
    PathBuf::from(mvm_core::config::default_microvm_cache_dir())
}

/// This variant's directory, whether or not it exists yet.
pub(super) fn variant_dir(variant: DefaultMicrovmVariant) -> PathBuf {
    cache_root().join(variant.cache_subdir())
}

/// One cached variant as it stands on disk.
pub(super) struct BootImageEntry {
    pub(super) variant: DefaultMicrovmVariant,
    pub(super) dir: PathBuf,
    /// Every file in [`DefaultMicrovmVariant::required_outputs`] is present.
    /// A partial directory is reported as incomplete rather than as an image,
    /// because the acquisition path will replace it on the next run.
    pub(super) complete: bool,
    /// Absent when the directory holds no sidecar, or one that will not parse.
    /// Distinct from a sidecar whose provenance fields are empty.
    pub(super) sidecar: Option<GuestSidecar>,
    pub(super) size_bytes: u64,
    /// Filesystem mtime of the sidecar, as an RFC 3339 timestamp. The fallback
    /// for an entry whose sidecar records no `built_at` — weaker evidence, so
    /// it is reported under its own name rather than as the recorded time.
    pub(super) sidecar_mtime: Option<String>,
}

impl BootImageEntry {
    /// Tag the entry claims, or `None` when it records none.
    pub(super) fn image_tag(&self) -> Option<&str> {
        self.sidecar
            .as_ref()
            .map(|s| s.image_tag.as_str())
            .filter(|t| !t.is_empty())
    }

    fn field<'a>(&'a self, pick: impl Fn(&'a GuestSidecar) -> &'a str) -> Option<&'a str> {
        self.sidecar
            .as_ref()
            .map(pick)
            .filter(|value| !value.is_empty())
    }

    pub(super) fn source(&self) -> Option<&str> {
        self.field(|s| s.source.as_str())
    }

    pub(super) fn generator_rev(&self) -> Option<&str> {
        self.field(|s| s.generator_rev.as_str())
    }

    /// When these bytes were produced or acquired: the recorded stamp when the
    /// producer left one, otherwise the sidecar's mtime.
    pub(super) fn acquired_at(&self) -> Option<&str> {
        self.field(|s| s.built_at.as_str())
            .or(self.sidecar_mtime.as_deref())
    }

    /// Zero means unrecorded, which is not a protocol version.
    pub(super) fn protocol_version(&self) -> Option<u8> {
        self.sidecar
            .as_ref()
            .map(|s| s.protocol_version)
            .filter(|v| *v != 0)
    }

    /// Whether the current process would boot these bytes rather than produce
    /// new ones. The acquisition path rebuilds or refetches whenever a required
    /// output is missing, so completeness is exactly that question.
    pub(super) fn would_use(&self) -> bool {
        self.complete
    }
}

/// Read both variants off disk. Never fails on a malformed entry — an
/// unreadable cache is a thing to report, not a thing to crash on.
pub(super) fn survey() -> Vec<BootImageEntry> {
    VARIANTS.into_iter().map(entry_for).collect()
}

fn entry_for(variant: DefaultMicrovmVariant) -> BootImageEntry {
    let dir = variant_dir(variant);
    let complete = variant
        .required_outputs()
        .iter()
        .all(|name| dir.join(name).is_file());
    BootImageEntry {
        variant,
        complete,
        sidecar: GuestSidecar::read_from_dir(&dir).ok().flatten(),
        size_bytes: directory_size(&dir),
        sidecar_mtime: sidecar_mtime(&dir),
        dir,
    }
}

/// Bytes held by the entry's own files. Shallow on purpose: a variant
/// directory is flat, and recursing would silently fold in whatever a future
/// staging or backup directory left behind.
fn directory_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

fn sidecar_mtime(dir: &Path) -> Option<String> {
    let modified = std::fs::metadata(GuestSidecar::path_in(dir))
        .ok()?
        .modified()
        .ok()?;
    Some(mvm_core::util::time::rfc3339_from_system_time(modified))
}

/// Provenance the installing host knows for certain, stamped into a sidecar
/// once the bytes are in place.
///
/// The build itself cannot supply these: a hermetic Nix build has no clock,
/// and "how did this reach this host" is not a fact about the build at all —
/// a published image is built locally *somewhere*, and calling that
/// `built-local` here is exactly the misreading `source` exists to prevent.
pub(super) struct AcquiredProvenance {
    pub(super) image_tag: String,
    pub(super) source: &'static str,
    pub(super) acquired_at: String,
}

impl AcquiredProvenance {
    pub(super) fn fetched(tag: &str) -> Self {
        Self {
            image_tag: tag.to_string(),
            source: "fetched",
            acquired_at: mvm_core::util::time::utc_now(),
        }
    }
}

/// Rewrite `dir`'s sidecar with the acquisition facts, leaving every build
/// fact the producer recorded untouched.
pub(super) fn stamp_provenance(dir: &Path, provenance: &AcquiredProvenance) -> Result<()> {
    let mut sidecar = GuestSidecar::read_from_dir(dir)
        .with_context(|| format!("read the sidecar in {}", dir.display()))?
        .with_context(|| {
            format!(
                "{} carries no {} sidecar; refusing to boot-tag an image that did not \
                 declare what it is",
                dir.display(),
                mvm_build::builder_vm::SIDECAR_FILENAME
            )
        })?;
    sidecar.image_tag = provenance.image_tag.clone();
    sidecar.source = provenance.source.to_string();
    sidecar.built_at = provenance.acquired_at.clone();
    sidecar
        .write_to_dir(dir)
        .with_context(|| format!("write the stamped sidecar to {}", dir.display()))?;
    Ok(())
}
