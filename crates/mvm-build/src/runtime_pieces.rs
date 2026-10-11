//! The launch-time pieces `mvmctl` assembles from a guest runtime — the
//! runtime overlay, the universal initramfs and one SDK sidecar per guest libc
//! — and the record of which guest-runtime archive each one came from.
//!
//! The archive is the one digest-keyed cache: `guest-runtime/v1/objects/<digest>`
//! holds the verified archive and its extracted tree, and every piece is
//! derived from such a tree. Each piece still lives in its own version-keyed
//! slot, because that is what the launch resolvers read, and records beside its
//! files the digest of the archive it was assembled from
//! ([`ARCHIVE_ORIGIN_FILE`]). That record says where the bytes came from; it is
//! not what decides reuse. The overlay and initramfs reuse a slot assembled
//! from the same digest, and the sidecar reuses one packed from the same
//! host-services sources, so an archive that rebuilt only other guest binaries
//! keeps the sidecar it already has, still naming the archive it came from.
//!
//! A piece acquired from the pinned image set lives under that set's root
//! instead and is reported as such.

use std::path::{Path, PathBuf};

use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetRole, MemberTarget};
use mvm_fs::initramfs::InitramfsArtifact;
use mvm_fs::overlay::{RuntimeOverlayArtifact, RuntimeOverlayLayout};
use mvm_fs::sdk_sidecar::{SdkSidecarArtifact, SdkSidecarLayout};

use crate::guest_runtime::{GuestRuntime, is_archive_digest};
use crate::initramfs::InitramfsBuildError;
use crate::published_image_set::{SetMemberCache, SetMemberCacheError};
use crate::runtime_overlay::RuntimeOverlayError;
use crate::sdk_sidecar::SdkSidecarBuildError;

/// File, inside a piece's version-keyed directory, naming the digest of the
/// guest-runtime archive the piece was assembled from.
pub const ARCHIVE_ORIGIN_FILE: &str = "GUEST_RUNTIME_ARCHIVE";

/// Directory under the mvm cache root holding the initramfs cache. The other
/// pieces' resolvers take the cache root itself.
pub const INITRAMFS_CACHE_DIR: &str = "initramfs";

/// Both SDK sidecar variants, in the order they are assembled and reported.
pub const SDK_SIDECAR_LIBCS: [GuestLibc; 2] = [GuestLibc::Glibc, GuestLibc::Musl];

/// One launch-time piece assembled from a guest runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePiece {
    RuntimeOverlay,
    Initramfs,
    SdkSidecar(GuestLibc),
}

impl RuntimePiece {
    /// Every piece, in the order `mvmctl doctor` reports them.
    pub const ALL: [RuntimePiece; 4] = [
        RuntimePiece::RuntimeOverlay,
        RuntimePiece::Initramfs,
        RuntimePiece::SdkSidecar(GuestLibc::Glibc),
        RuntimePiece::SdkSidecar(GuestLibc::Musl),
    ];

    pub fn label(self) -> String {
        match self {
            RuntimePiece::RuntimeOverlay => "runtime overlay".to_string(),
            RuntimePiece::Initramfs => "initramfs".to_string(),
            RuntimePiece::SdkSidecar(libc) => format!("SDK sidecar {libc}"),
        }
    }

    /// The version-keyed directory a source assembly installs this piece into.
    pub fn local_dir(self, cache_root: &Path, version: &str, arch: GuestArch) -> PathBuf {
        let arch = arch.to_string();
        match self {
            RuntimePiece::RuntimeOverlay => {
                RuntimeOverlayLayout::under(cache_root, version, &arch).artifact_dir
            }
            RuntimePiece::Initramfs => {
                mvm_fs::initramfs::InitramfsResolver::new(initramfs_cache_root(cache_root), version)
                    .artifact_dir(&arch)
            }
            RuntimePiece::SdkSidecar(libc) => {
                SdkSidecarLayout::under(cache_root, version, &arch, libc).artifact_dir
            }
        }
    }

    /// The file whose presence means the version-keyed slot holds this piece.
    fn local_image(self, cache_root: &Path, version: &str, arch: GuestArch) -> PathBuf {
        match self {
            RuntimePiece::RuntimeOverlay => {
                RuntimeOverlayLayout::under(cache_root, version, &arch.to_string()).overlay_ext4
            }
            RuntimePiece::Initramfs => self
                .local_dir(cache_root, version, arch)
                .join(mvm_fs::initramfs::INITRAMFS_IMAGE_FILE),
            RuntimePiece::SdkSidecar(libc) => {
                SdkSidecarLayout::under(cache_root, version, &arch.to_string(), libc).image
            }
        }
    }

    /// The image-set member this piece is published as.
    fn image_set_role(self) -> ImageSetRole {
        match self {
            RuntimePiece::RuntimeOverlay => ImageSetRole::RuntimeOverlay,
            RuntimePiece::Initramfs => ImageSetRole::Initramfs,
            RuntimePiece::SdkSidecar(libc) => ImageSetRole::SdkSidecar(libc),
        }
    }

    /// The cache root this piece's resolvers, and its image-set install
    /// records, are keyed under.
    fn resolver_cache_root(self, cache_root: &Path) -> PathBuf {
        match self {
            RuntimePiece::Initramfs => initramfs_cache_root(cache_root),
            RuntimePiece::RuntimeOverlay | RuntimePiece::SdkSidecar(_) => cache_root.to_path_buf(),
        }
    }
}

/// The leading twelve characters of an archive digest, as status lines show it.
pub fn short_digest(digest: &str) -> &str {
    digest.get(..12).unwrap_or(digest)
}

/// The initramfs cache under the mvm cache root.
pub fn initramfs_cache_root(cache_root: &Path) -> PathBuf {
    cache_root.join(INITRAMFS_CACHE_DIR)
}

#[derive(Debug, thiserror::Error)]
pub enum PieceOriginError {
    #[error("reading {}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{} does not hold an archive digest", path.display())]
    InvalidRecord { path: PathBuf },
    #[error(transparent)]
    ImageSet(#[from] SetMemberCacheError),
}

/// Record that the piece in `dir` was assembled from the archive `digest`.
pub fn record_archive_origin(dir: &Path, digest: &str) -> std::io::Result<()> {
    if !is_archive_digest(digest) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{digest:?} is not an archive digest"),
        ));
    }
    std::fs::write(dir.join(ARCHIVE_ORIGIN_FILE), format!("{digest}\n"))
}

/// The archive digest recorded in `dir`, if any. A record that is present but
/// is not a digest is an error, not an absence: something other than an
/// assembler wrote it.
pub fn archive_origin(dir: &Path) -> Result<Option<String>, PieceOriginError> {
    let path = dir.join(ARCHIVE_ORIGIN_FILE);
    match std::fs::read_to_string(&path) {
        Ok(body) => {
            let digest = body.trim();
            if is_archive_digest(digest) {
                Ok(Some(digest.to_string()))
            } else {
                Err(PieceOriginError::InvalidRecord { path })
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(PieceOriginError::Io { path, source }),
    }
}

/// Where the copy of a piece a launch would attach came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PieceOrigin {
    /// Assembled on this host from the guest-runtime archive with this digest.
    Archive { digest: String },
    /// A version-keyed copy that names no archive: seeded from another cache
    /// without its record, or written before pieces recorded one.
    LocalUnrecorded,
    /// Installed from the pinned image set, at the member's own version.
    ImageSet { version: String },
    /// Not in the cache.
    Missing,
}

/// Where `piece` would be attached from, read from the cache alone and in the
/// order the launch resolvers look: the version-keyed slot, then the member of
/// the pinned image set `set`. Reads presence and records only; nothing is
/// hashed, so this answers a diagnostic, not whether the bytes are sound.
pub fn piece_origin(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    piece: RuntimePiece,
    set: &SetMemberCache,
) -> Result<PieceOrigin, PieceOriginError> {
    if piece.local_image(cache_root, version, arch).is_file() {
        return Ok(
            match archive_origin(&piece.local_dir(cache_root, version, arch))? {
                Some(digest) => PieceOrigin::Archive { digest },
                None => PieceOrigin::LocalUnrecorded,
            },
        );
    }
    match set.installed_version(
        &piece.resolver_cache_root(cache_root),
        piece.image_set_role(),
        MemberTarget::Arch(arch),
    ) {
        Ok(version) => Ok(PieceOrigin::ImageSet {
            version: version.into(),
        }),
        Err(SetMemberCacheError::NotInstalled { .. }) => Ok(PieceOrigin::Missing),
        Err(error) => Err(error.into()),
    }
}

/// Remove `piece`'s version-keyed copy so the next assembly rebuilds it rather
/// than reusing it. An absent copy is not an error.
pub fn discard_local_piece(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    piece: RuntimePiece,
) -> std::io::Result<()> {
    match std::fs::remove_dir_all(piece.local_dir(cache_root, version, arch)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AssembleError {
    #[error("assemble the runtime overlay: {0}")]
    RuntimeOverlay(#[from] RuntimeOverlayError),
    #[error("assemble the initramfs: {0}")]
    Initramfs(#[from] InitramfsBuildError),
    #[error("pack the SDK sidecar: {0}")]
    SdkSidecar(#[from] SdkSidecarBuildError),
}

/// Every piece assembled from one guest runtime.
#[derive(Debug, Clone)]
pub struct AssembledPieces {
    pub runtime_overlay: RuntimeOverlayArtifact,
    pub initramfs: InitramfsArtifact,
    pub sdk_sidecars: Vec<SdkSidecarArtifact>,
}

/// Assemble every launch-time piece from `runtime`, reusing any slot already
/// assembled from it. This is what bootstrap prewarms with; the explicit
/// `build` verbs assemble the one piece they name through the same functions.
pub fn assemble_runtime_pieces(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    runtime: &GuestRuntime,
) -> Result<AssembledPieces, AssembleError> {
    let runtime_overlay = crate::runtime_overlay::build_runtime_overlay_from_guest_runtime(
        cache_root, version, arch, runtime,
    )?;
    let initramfs = crate::initramfs::build_initramfs_from_guest_runtime(
        &initramfs_cache_root(cache_root),
        version,
        arch,
        runtime,
    )?;
    let sdk_sidecars = pack_sdk_sidecars(cache_root, version, arch, runtime)?;
    Ok(AssembledPieces {
        runtime_overlay,
        initramfs,
        sdk_sidecars,
    })
}

/// Pack both SDK sidecar variants from `runtime`.
pub fn pack_sdk_sidecars(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    runtime: &GuestRuntime,
) -> Result<Vec<SdkSidecarArtifact>, SdkSidecarBuildError> {
    SDK_SIDECAR_LIBCS
        .into_iter()
        .map(|libc| {
            crate::sdk_sidecar::build_sdk_sidecar_from_guest_runtime(
                cache_root, version, arch, libc, runtime,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    #[test]
    fn an_origin_record_round_trips_and_refuses_what_is_not_a_digest() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(archive_origin(dir.path()).unwrap(), None);
        record_archive_origin(dir.path(), &digest('a')).unwrap();
        assert_eq!(archive_origin(dir.path()).unwrap(), Some(digest('a')));

        assert!(record_archive_origin(dir.path(), "../outside").is_err());
        std::fs::write(dir.path().join(ARCHIVE_ORIGIN_FILE), "not a digest\n").unwrap();
        assert!(matches!(
            archive_origin(dir.path()),
            Err(PieceOriginError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn a_local_piece_reports_the_archive_it_names_or_that_it_names_none() {
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"root"));
        for piece in RuntimePiece::ALL {
            assert_eq!(
                piece_origin(cache.path(), "1.2.3", arch, piece, &set).unwrap(),
                PieceOrigin::Missing,
                "{}",
                piece.label()
            );
            let image = piece.local_image(cache.path(), "1.2.3", arch);
            std::fs::create_dir_all(image.parent().unwrap()).unwrap();
            std::fs::write(&image, b"image").unwrap();
            assert_eq!(
                piece_origin(cache.path(), "1.2.3", arch, piece, &set).unwrap(),
                PieceOrigin::LocalUnrecorded,
                "{}",
                piece.label()
            );
            record_archive_origin(&piece.local_dir(cache.path(), "1.2.3", arch), &digest('b'))
                .unwrap();
            assert_eq!(
                piece_origin(cache.path(), "1.2.3", arch, piece, &set).unwrap(),
                PieceOrigin::Archive {
                    digest: digest('b')
                },
                "{}",
                piece.label()
            );
            // Another version's slot is not this one.
            assert_eq!(
                piece_origin(cache.path(), "1.2.4", arch, piece, &set).unwrap(),
                PieceOrigin::Missing
            );
        }
    }

    #[test]
    fn an_image_set_member_is_reported_at_its_own_version() {
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::Aarch64;
        let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"root"));
        for piece in RuntimePiece::ALL {
            set.record(
                &piece.resolver_cache_root(cache.path()),
                piece.image_set_role(),
                MemberTarget::Arch(arch),
                &crate::published_image_set::MemberVersion::parse("0.9.0").unwrap(),
            )
            .unwrap();
            assert_eq!(
                piece_origin(cache.path(), "1.2.3", arch, piece, &set).unwrap(),
                PieceOrigin::ImageSet {
                    version: "0.9.0".to_string()
                },
                "{}",
                piece.label()
            );
        }
    }

    #[test]
    fn the_version_keyed_slot_wins_over_the_image_set_like_the_launch_resolvers() {
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let set = SetMemberCache::for_root(mvm_core::packs::Sha256Hex::from_bytes(b"root"));
        let piece = RuntimePiece::SdkSidecar(GuestLibc::Musl);
        set.record(
            cache.path(),
            piece.image_set_role(),
            MemberTarget::Arch(arch),
            &crate::published_image_set::MemberVersion::parse("0.9.0").unwrap(),
        )
        .unwrap();
        let image = piece.local_image(cache.path(), "1.2.3", arch);
        std::fs::create_dir_all(image.parent().unwrap()).unwrap();
        std::fs::write(&image, b"image").unwrap();
        record_archive_origin(&piece.local_dir(cache.path(), "1.2.3", arch), &digest('c')).unwrap();
        assert_eq!(
            piece_origin(cache.path(), "1.2.3", arch, piece, &set).unwrap(),
            PieceOrigin::Archive {
                digest: digest('c')
            }
        );
    }

    #[test]
    fn discarding_a_piece_removes_only_its_own_slot() {
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        for piece in RuntimePiece::ALL {
            let image = piece.local_image(cache.path(), "1.2.3", arch);
            std::fs::create_dir_all(image.parent().unwrap()).unwrap();
            std::fs::write(&image, b"image").unwrap();
        }
        let glibc = RuntimePiece::SdkSidecar(GuestLibc::Glibc);
        discard_local_piece(cache.path(), "1.2.3", arch, glibc).unwrap();
        discard_local_piece(cache.path(), "1.2.3", arch, glibc).unwrap();
        for piece in RuntimePiece::ALL {
            assert_eq!(
                piece.local_image(cache.path(), "1.2.3", arch).is_file(),
                piece != glibc,
                "{}",
                piece.label()
            );
        }
    }
}
