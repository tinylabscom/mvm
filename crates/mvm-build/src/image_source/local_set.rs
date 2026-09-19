//! Reading back a set built from the selected image checkout.
//!
//! The manifest is the one the image repository's emitter writes beside the
//! artifacts, in the schema a released set uses. It is parsed and checked by
//! `mvm_core::image_set::verify_local_image_set`; this module supplies what
//! only the host can: the selection re-verified, the paired mvm checkout's
//! identity read fresh, and the manifest's bytes read from a regular file.

use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;
use mvm_core::image_set::{
    ImageSetError, ImageSetRole, LOCAL_SET_MANIFEST_NAME, LocalCheckouts, LocalImageSet,
    LocalImageSetVerification, RepoIdentity, verify_local_image_set,
};
use thiserror::Error;

use super::{ImageSourceError, LocalImageCheckout, git};

/// Why a locally built set was not read.
#[derive(Debug, Error)]
pub enum LocalSetError {
    #[error(transparent)]
    Selection(#[from] ImageSourceError),
    #[error("mvm checkout {}: {detail}", .root.display())]
    MvmCheckout { root: PathBuf, detail: String },
    #[error("{}: cannot read the image set manifest: {source}", .path.display())]
    ManifestUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(
        "{}: not a regular file; a set's manifest must live inside its directory",
        .path.display()
    )]
    ManifestNotRegularFile { path: PathBuf },
    #[error(
        "local image set in {}: refused at the {} stage: {source}",
        .dir.display(),
        .source.stage()
    )]
    Refused { dir: PathBuf, source: ImageSetError },
}

impl LocalSetError {
    /// The verifier's refusal, when that is what stopped the read.
    #[must_use]
    pub fn refusal(&self) -> Option<&ImageSetError> {
        match self {
            Self::Refused { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// What a caller wants from a locally built set.
#[derive(Debug, Clone, Copy)]
pub struct LocalSetRequest<'a> {
    /// The mvm checkout paired with the image checkout. Its guest and host
    /// binaries are the ones inside the set.
    pub mvm_checkout: &'a Path,
    /// The directory the emitter wrote: the manifest and every artifact.
    pub set_dir: &'a Path,
    pub arch: GuestArch,
    /// Roles the caller is about to use; a set without any of them is refused.
    pub roles: &'a [ImageSetRole],
}

impl LocalImageCheckout {
    /// Read the set in `request.set_dir`, built from this checkout and the
    /// paired mvm checkout.
    ///
    /// The selection is re-verified first, so a retargeted path or an edit
    /// since selection is refused before anything else is read. The set is
    /// then accepted only if its manifest records exactly the identities both
    /// checkouts have now: a set built before either tree changed is stale,
    /// however well-formed it is. The result is always the `local-dev` tier.
    pub fn read_local_image_set(
        &self,
        request: &LocalSetRequest<'_>,
    ) -> Result<LocalImageSet, LocalSetError> {
        self.reverify()?;
        let current = LocalCheckouts {
            images: self.identity().clone(),
            mvm: open_mvm_checkout(request.mvm_checkout)?.1,
        };
        let manifest_bytes = read_manifest(request.set_dir)?;
        let verification = LocalImageSetVerification::new(
            &manifest_bytes,
            request.set_dir,
            &current,
            request.arch,
        )
        .require_roles(request.roles);
        verify_local_image_set(&verification).map_err(|source| LocalSetError::Refused {
            dir: request.set_dir.to_path_buf(),
            source,
        })
    }
}

/// The paired mvm checkout's canonical root and identity, read now. Held to
/// the same shape as an image checkout: the root of its own git work tree.
pub(super) fn open_mvm_checkout(given: &Path) -> Result<(PathBuf, RepoIdentity), LocalSetError> {
    let failed = |root: &Path, detail: String| LocalSetError::MvmCheckout {
        root: root.to_path_buf(),
        detail,
    };
    let root = std::fs::canonicalize(given).map_err(|e| failed(given, e.to_string()))?;
    let toplevel = git::toplevel(&root).map_err(|detail| failed(&root, detail))?;
    let toplevel = std::fs::canonicalize(&toplevel).unwrap_or_else(|_| PathBuf::from(toplevel));
    if toplevel != root {
        return Err(failed(
            &root,
            format!(
                "not the root of its git checkout (the root is {})",
                toplevel.display()
            ),
        ));
    }
    let identity = git::probe_identity(&root).map_err(|detail| failed(&root, detail))?;
    Ok((root, identity))
}

/// The manifest's bytes, from a regular file directly inside the set's
/// directory. A link would let the set's directory vouch for a manifest kept
/// somewhere else.
fn read_manifest(set_dir: &Path) -> Result<Vec<u8>, LocalSetError> {
    let path = set_dir.join(LOCAL_SET_MANIFEST_NAME);
    let is_file = std::fs::symlink_metadata(&path)
        .map(|meta| meta.file_type().is_file())
        .map_err(|source| LocalSetError::ManifestUnreadable {
            path: path.clone(),
            source,
        })?;
    if !is_file {
        return Err(LocalSetError::ManifestNotRegularFile { path });
    }
    std::fs::read(&path).map_err(|source| LocalSetError::ManifestUnreadable { path, source })
}
