//! Where the guest images come from: the released set, or a local image
//! checkout the contributor named.
//!
//! The released set is the default and the only source a release build or a
//! production admission accepts. A contributor working on images names their
//! `mvm-images` checkout with [`MVM_IMAGES_DIR_ENV`]; nothing looks for one.
//! The selection is explicit in both directions:
//!
//! - a configured path that is not a usable checkout is an error, never a
//!   quiet return to the released set;
//! - a release build refuses the variable outright, before it can matter,
//!   because "which images did this binary boot" must not depend on the shell
//!   it was started from.
//!
//! An environment variable rather than a config key or a flag, for the same
//! reason `MVM_BOOT_IMAGE` and `MVM_BUILDER_BACKEND` are: it is scoped to one
//! shell, so two paired worktrees select two checkouts without editing shared
//! configuration, and it reaches every child process a build spawns.
//!
//! A resolved checkout records its canonical root, commit and working-tree
//! state. Consumers re-check that record with
//! [`LocalImageCheckout::reverify`] before trusting anything built from it, so
//! a symlink retargeted or a tree edited between selection and use is caught
//! rather than attributed to the recorded identity.
//!
//! A set built from the checkout is read back through [`LocalSetRequest`],
//! which re-verifies the selection, re-reads the paired mvm checkout, and
//! accepts the set's manifest only if it names exactly those two identities.
//! [`LocalImageCache`] keeps such sets, keyed on everything they were built
//! from, so an unchanged pair of checkouts is built once.

use std::path::{Path, PathBuf};

use mvm_core::image_set::ImageTrustTier;
use mvm_core::plan::Variant;
use thiserror::Error;

use crate::artifact_acquisition::DistributionChannel;

mod cache;
mod git;
mod local_set;

pub use cache::{
    CacheLookup, CachedImageSet, ENTRY_RECORD_NAME, EntryContext, FlakeAttr, FlakeLockDigest,
    ImageBuildRole, ImageBuildTarget, KeyInputs, LOCAL_IMAGE_CACHE_DIR, LocalImageCache,
    LocalImageCacheError, LocalImageCacheKey, PublishOutcome, StagedEntry, ToolchainPins,
};
pub use git::{RepoIdentity, WorktreeState, probe_identity};
pub use local_set::{LocalSetError, LocalSetRequest};

/// The variable naming a local `mvm-images` checkout.
pub const MVM_IMAGES_DIR_ENV: &str = "MVM_IMAGES_DIR";

/// The in-tree builder image flake, whose presence marks an mvm checkout that
/// still builds its own images.
const IN_TREE_IMAGE_MARKER: &str = "nix/images/builder-vm/flake.nix";

/// Files every `mvm-images` checkout carries at its root, relative paths. A
/// directory missing any of them is not one, whatever else it holds.
pub const IMAGES_CHECKOUT_MARKERS: &[&str] = &[
    "flake.nix",
    "flake.lock",
    "kernel/flake.nix",
    "images/builder-vm/image.nix",
    "images/default-tenant/image.nix",
    "images/runtime-overlay/image.nix",
    "images/initramfs/image.nix",
];

/// Why an image source was refused.
#[derive(Debug, Error)]
pub enum ImageSourceError {
    #[error(
        "${MVM_IMAGES_DIR_ENV} is set, but this is a release build of mvmctl, which boots only \
         verified released image sets; unset ${MVM_IMAGES_DIR_ENV}, or use a contributor build \
         to boot images from a local checkout"
    )]
    RefusedInReleaseBuild,
    #[error(
        "${MVM_IMAGES_DIR_ENV} is set, and a production admission boots only verified released \
         image sets; a local checkout is {tier}. Unset ${MVM_IMAGES_DIR_ENV} for this run",
        tier = ImageTrustTier::LocalDev
    )]
    RefusedInProduction,
    #[error("${MVM_IMAGES_DIR_ENV}={}: cannot resolve the path: {source}", .path.display())]
    Unresolvable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("${MVM_IMAGES_DIR_ENV}={}: not a directory", .path.display())]
    NotADirectory { path: PathBuf },
    #[error(
        "${MVM_IMAGES_DIR_ENV}={}: not an mvm-images checkout (no regular file {marker})",
        .root.display()
    )]
    NotAnImagesCheckout { root: PathBuf, marker: &'static str },
    #[error(
        "${MVM_IMAGES_DIR_ENV}={}: {marker} is a symlink; an image checkout's own sources \
         must live inside it",
        .root.display()
    )]
    SymlinkedMarker { root: PathBuf, marker: &'static str },
    #[error("${MVM_IMAGES_DIR_ENV}={}: not a git checkout: {detail}", .root.display())]
    NotAGitCheckout { root: PathBuf, detail: String },
    #[error(
        "${MVM_IMAGES_DIR_ENV}={}: not the root of its git checkout (the root is {})",
        .root.display(),
        .toplevel.display()
    )]
    NotTheRepositoryRoot { root: PathBuf, toplevel: PathBuf },
    #[error("${MVM_IMAGES_DIR_ENV}={}: reading the checkout identity: {detail}", .root.display())]
    Identity { root: PathBuf, detail: String },
    #[error(
        "${MVM_IMAGES_DIR_ENV}={} now resolves to {}, not the checkout selected at {}",
        .requested.display(),
        .now.display(),
        .recorded.display()
    )]
    Substituted {
        requested: PathBuf,
        recorded: PathBuf,
        now: PathBuf,
    },
    #[error(
        "{}: the checkout changed since it was selected (was {was}, now {now}); \
         select it again",
        .root.display()
    )]
    Changed {
        root: PathBuf,
        was: Box<RepoIdentity>,
        now: Box<RepoIdentity>,
    },
}

/// Where the images come from, once selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageSource {
    /// The set the checked-in image lock pins, admitted only after its manifest
    /// verifies.
    Released,
    /// A local image checkout, named explicitly.
    LocalCheckout(LocalImageCheckout),
    /// The image flakes still inside the mvm checkout a contributor build was
    /// compiled from. The default for such a build until those flakes are
    /// removed; never selected for a release build.
    InTree { root: PathBuf },
}

impl ImageSource {
    /// The tier this source is classified into. The released source is
    /// classified `verified-release` because the only path that consumes it
    /// verifies the manifest first; nothing here verifies anything. Anything
    /// built locally, in either checkout, is `local-dev`.
    #[must_use]
    pub fn tier(&self) -> ImageTrustTier {
        match self {
            Self::Released => ImageTrustTier::VerifiedRelease,
            Self::LocalCheckout(_) | Self::InTree { .. } => ImageTrustTier::LocalDev,
        }
    }
}

/// A validated local `mvm-images` checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalImageCheckout {
    /// The path as given, kept so [`Self::reverify`] can tell whether it still
    /// resolves to the same place.
    requested: PathBuf,
    /// Canonical root: absolute, no `..`, no symlink components.
    root: PathBuf,
    identity: RepoIdentity,
}

impl LocalImageCheckout {
    /// Validate `requested` as an `mvm-images` checkout and record its
    /// identity.
    pub fn open(requested: &Path) -> Result<Self, ImageSourceError> {
        let root = canonical_directory(requested)?;
        require_markers(&root)?;
        require_repository_root(&root)?;
        let identity = probe_identity(&root).map_err(|detail| ImageSourceError::Identity {
            root: root.clone(),
            detail,
        })?;
        Ok(Self {
            requested: requested.to_path_buf(),
            root,
            identity,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn identity(&self) -> &RepoIdentity {
        &self.identity
    }

    /// Confirm the selection still names the same bytes: the requested path
    /// resolves to the recorded root, the checkout is still an image checkout,
    /// and its commit and working-tree state are unchanged.
    pub fn reverify(&self) -> Result<(), ImageSourceError> {
        let now = canonical_directory(&self.requested)?;
        if now != self.root {
            return Err(ImageSourceError::Substituted {
                requested: self.requested.clone(),
                recorded: self.root.clone(),
                now,
            });
        }
        let current = Self::open(&self.requested)?;
        if current.identity != self.identity {
            return Err(ImageSourceError::Changed {
                root: self.root.clone(),
                was: Box::new(self.identity.clone()),
                now: Box::new(current.identity),
            });
        }
        Ok(())
    }
}

/// The local checkout the environment names, if any. Empty counts as unset.
#[must_use]
pub fn configured_images_dir() -> Option<PathBuf> {
    let raw = std::env::var_os(MVM_IMAGES_DIR_ENV)?;
    (!raw.is_empty()).then(|| PathBuf::from(raw))
}

/// Select the image source for a binary of `channel`, given the configured
/// checkout path.
///
/// A configured path is either a valid local checkout or an error; it never
/// falls back to another source. Without one, a contributor build whose
/// checkout still carries the in-tree image flakes builds from those, and
/// every other binary uses the released set.
pub fn resolve_image_source(
    channel: DistributionChannel,
    configured: Option<&Path>,
) -> Result<ImageSource, ImageSourceError> {
    select_image_source(channel, configured, in_tree_images(channel))
}

/// [`resolve_image_source`] with the in-tree answer passed in, so the choice
/// is testable without depending on the checkout the tests run from.
pub fn select_image_source(
    channel: DistributionChannel,
    configured: Option<&Path>,
    in_tree: Option<PathBuf>,
) -> Result<ImageSource, ImageSourceError> {
    if let Some(path) = configured {
        refuse_in_release_build(channel, Some(path))?;
        return LocalImageCheckout::open(path).map(ImageSource::LocalCheckout);
    }
    Ok(match in_tree {
        Some(root) if channel.permits_automatic_builds() => ImageSource::InTree { root },
        _ => ImageSource::Released,
    })
}

/// The mvm checkout of a contributor build, when it still carries the in-tree
/// image flakes.
#[must_use]
pub fn in_tree_images(channel: DistributionChannel) -> Option<PathBuf> {
    mvm_source_checkout(channel).filter(|root| root.join(IN_TREE_IMAGE_MARKER).is_file())
}

/// A release build refuses a configured local checkout, valid or not.
pub fn refuse_in_release_build(
    channel: DistributionChannel,
    configured: Option<&Path>,
) -> Result<(), ImageSourceError> {
    match (channel, configured) {
        (DistributionChannel::Release, Some(_)) => Err(ImageSourceError::RefusedInReleaseBuild),
        _ => Ok(()),
    }
}

/// A production admission refuses while a local checkout is configured,
/// valid or not: the tier of what would boot is not established by whether
/// the path happens to be usable.
pub fn refuse_in_production(
    variant: Variant,
    configured: Option<&Path>,
) -> Result<(), ImageSourceError> {
    if variant.is_prod() && configured.is_some() {
        return Err(ImageSourceError::RefusedInProduction);
    }
    Ok(())
}

/// The mvm checkout a contributor build was compiled from, when it is still
/// there. A release build has none: its source is the release tag.
#[must_use]
pub fn mvm_source_checkout(channel: DistributionChannel) -> Option<PathBuf> {
    if !channel.permits_automatic_builds() {
        return None;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.parent()?;
    root.join("Cargo.toml")
        .is_file()
        .then(|| root.to_path_buf())
}

fn canonical_directory(requested: &Path) -> Result<PathBuf, ImageSourceError> {
    let root =
        std::fs::canonicalize(requested).map_err(|source| ImageSourceError::Unresolvable {
            path: requested.to_path_buf(),
            source,
        })?;
    if !root.is_dir() {
        return Err(ImageSourceError::NotADirectory { path: root });
    }
    Ok(root)
}

/// Each marker must be a regular file inside the root, not a link to one
/// elsewhere: a checkout assembled from links is not the tree its commit names.
fn require_markers(root: &Path) -> Result<(), ImageSourceError> {
    for &marker in IMAGES_CHECKOUT_MARKERS {
        let meta = std::fs::symlink_metadata(root.join(marker)).ok();
        match meta {
            Some(m) if m.file_type().is_symlink() => {
                return Err(ImageSourceError::SymlinkedMarker {
                    root: root.to_path_buf(),
                    marker,
                });
            }
            Some(m) if m.is_file() => {}
            _ => {
                return Err(ImageSourceError::NotAnImagesCheckout {
                    root: root.to_path_buf(),
                    marker,
                });
            }
        }
    }
    Ok(())
}

fn require_repository_root(root: &Path) -> Result<(), ImageSourceError> {
    let toplevel = git::toplevel(root).map_err(|detail| ImageSourceError::NotAGitCheckout {
        root: root.to_path_buf(),
        detail,
    })?;
    let toplevel = std::fs::canonicalize(&toplevel).unwrap_or_else(|_| PathBuf::from(toplevel));
    if toplevel != root {
        return Err(ImageSourceError::NotTheRepositoryRoot {
            root: root.to_path_buf(),
            toplevel,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
