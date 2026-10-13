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
//! A release binary has no tree to build an archive from. It assembles the
//! same pieces from the guest runtime its own release ships
//! ([`assemble_release_runtime_pieces`]), into the same version-keyed slots,
//! and then records that it adopted that archive
//! ([`adopted_release_archive`]).
//!
//! These slots are the only place a launch looks. The image set carries no
//! guest runtime, so a piece that is missing or no longer verifies is refused
//! with the command that assembles it, never replaced by a copy built from
//! another tree.

use std::path::{Path, PathBuf};

use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use mvm_fs::initramfs::InitramfsArtifact;
use mvm_fs::overlay::{RuntimeOverlayArtifact, RuntimeOverlayLayout};
use mvm_fs::sdk_sidecar::{SdkSidecarArtifact, SdkSidecarLayout};

use crate::guest_runtime::{GuestRuntime, GuestRuntimeError, is_archive_digest};
use crate::initramfs::InitramfsBuildError;
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
    /// Not in the cache.
    Missing,
}

/// Where `piece` would be attached from, read from the cache alone: the
/// version-keyed slot the launch resolvers read. Reads presence and records
/// only; nothing is hashed, so this answers a diagnostic, not whether the
/// bytes are sound.
pub fn piece_origin(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    piece: RuntimePiece,
) -> Result<PieceOrigin, PieceOriginError> {
    if !piece.local_image(cache_root, version, arch).is_file() {
        return Ok(PieceOrigin::Missing);
    }
    Ok(
        match archive_origin(&piece.local_dir(cache_root, version, arch))? {
            Some(digest) => PieceOrigin::Archive { digest },
            None => PieceOrigin::LocalUnrecorded,
        },
    )
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
    #[error("install the release guest runtime: {0}")]
    GuestRuntime(#[from] GuestRuntimeError),
    #[error("install the OCI guest runtime from the release guest runtime: {0}")]
    OciGuestRuntime(#[from] crate::guest_agent_build::GuestAgentBuildError),
    #[error("record the adopted release guest runtime: {0}")]
    Record(#[from] std::io::Error),
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

/// Directory, under the mvm cache root, holding one record per release
/// version and architecture whose pieces were assembled from that release's
/// guest runtime.
pub const RELEASE_ADOPTION_DIR: &str = "guest-runtime/v1/releases";

/// The record naming the release guest-runtime archive `version`'s pieces for
/// `arch` were assembled from.
pub fn release_adoption_record(cache_root: &Path, version: &str, arch: GuestArch) -> PathBuf {
    cache_root
        .join(RELEASE_ADOPTION_DIR)
        .join(version)
        .join(arch.to_string())
}

/// The digest of the release guest-runtime archive this version adopted for
/// `arch`, if it adopted one. Reads the record alone; nothing is hashed. A
/// record that is present but holds no digest is an error, not an absence.
pub fn adopted_release_archive(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<Option<String>, PieceOriginError> {
    let path = release_adoption_record(cache_root, version, arch);
    match std::fs::read_to_string(&path) {
        Ok(body) if is_archive_digest(body.trim()) => Ok(Some(body.trim().to_string())),
        Ok(_) => Err(PieceOriginError::InvalidRecord { path }),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(PieceOriginError::Io { path, source }),
    }
}

/// What [`assemble_release_runtime_pieces`] produced.
#[derive(Debug, Clone)]
pub struct ReleaseAssembly {
    /// The release archive's verified extraction.
    pub runtime: GuestRuntime,
    pub pieces: AssembledPieces,
}

/// Assemble every launch-time piece from a CLI release's own guest runtime.
///
/// `archive` must already be authenticated (see
/// [`crate::guest_runtime::install_release_guest_runtime`]). The archive is
/// installed into the digest-keyed store, every piece is assembled from it
/// through the same assemblers a source build uses — the overlay's verity
/// tree and roothash computed here on the host, as claim 3 requires — and
/// the OCI guest runtime is installed from the same members. The adoption
/// record is written last, so it never names an archive whose pieces did not
/// all assemble.
pub fn assemble_release_runtime_pieces(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    archive: &Path,
) -> Result<ReleaseAssembly, AssembleError> {
    let runtime =
        crate::guest_runtime::install_release_guest_runtime(cache_root, archive, version, arch)?;
    let pieces = assemble_runtime_pieces(cache_root, version, arch, &runtime)?;
    install_oci_guest_runtime(cache_root, version, arch, &runtime)?;
    let record = release_adoption_record(cache_root, version, arch);
    if let Some(parent) = record.parent() {
        std::fs::create_dir_all(parent)?;
    }
    mvm_core::util::atomic_io::atomic_write(&record, format!("{}\n", runtime.digest).as_bytes())
        .map_err(std::io::Error::other)?;
    Ok(ReleaseAssembly { runtime, pieces })
}

/// Install the four binaries an OCI rootfs is given from `runtime`, under the
/// key a launch outside an explicit source build looks them up by: the CLI's
/// own version.
pub fn install_oci_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    runtime: &GuestRuntime,
) -> Result<(), crate::guest_agent_build::GuestAgentBuildError> {
    let bin = |name: &str| runtime.root.join(arch.to_string()).join("bin").join(name);
    crate::guest_agent_build::install_into_cache(
        crate::guest_agent_build::GuestRuntimeBinaryPaths {
            agent: &bin("mvm-guest-agent"),
            netinit: &bin("mvm-guest-netinit"),
            egress_client: &bin("mvm-egress-client"),
            entrypoint_runner: &bin("mvm-oci-entrypoint"),
        },
        &cache_root.join("oci"),
        version,
        arch,
    )
    .map(|_| ())
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
        for piece in RuntimePiece::ALL {
            assert_eq!(
                piece_origin(cache.path(), "1.2.3", arch, piece).unwrap(),
                PieceOrigin::Missing,
                "{}",
                piece.label()
            );
            let image = piece.local_image(cache.path(), "1.2.3", arch);
            std::fs::create_dir_all(image.parent().unwrap()).unwrap();
            std::fs::write(&image, b"image").unwrap();
            assert_eq!(
                piece_origin(cache.path(), "1.2.3", arch, piece).unwrap(),
                PieceOrigin::LocalUnrecorded,
                "{}",
                piece.label()
            );
            record_archive_origin(&piece.local_dir(cache.path(), "1.2.3", arch), &digest('b'))
                .unwrap();
            assert_eq!(
                piece_origin(cache.path(), "1.2.3", arch, piece).unwrap(),
                PieceOrigin::Archive {
                    digest: digest('b')
                },
                "{}",
                piece.label()
            );
            // Another version's slot is not this one.
            assert_eq!(
                piece_origin(cache.path(), "1.2.4", arch, piece).unwrap(),
                PieceOrigin::Missing
            );
        }
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

    /// A slot that cannot be removed is reported, not taken for already gone.
    /// Only an absent slot is success: a caller that discards a piece so the
    /// next assembly rebuilds it would otherwise go on to reuse the copy it
    /// believes it removed.
    #[test]
    fn discarding_a_slot_that_cannot_be_removed_is_an_error() {
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let piece = RuntimePiece::Initramfs;
        let slot = piece.local_dir(cache.path(), "1.2.3", arch);
        std::fs::create_dir_all(slot.parent().unwrap()).unwrap();
        // A file where the directory belongs: removal fails with something
        // other than NotFound.
        std::fs::write(&slot, b"not a directory").unwrap();

        let error = discard_local_piece(cache.path(), "1.2.3", arch, piece)
            .expect_err("a slot that could not be removed must not report success");
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(
            slot.is_file(),
            "the failed discard must leave the slot alone"
        );
    }

    /// The labels are what `mvmctl doctor` prints per piece, so each one names
    /// its piece and no two collide.
    #[test]
    fn each_piece_carries_its_own_label() {
        let labels: Vec<String> = RuntimePiece::ALL.iter().map(|p| p.label()).collect();
        assert_eq!(
            labels,
            [
                "runtime overlay",
                "initramfs",
                "SDK sidecar glibc",
                "SDK sidecar musl",
            ]
        );
    }

    /// The fresh one-clone install, end to end on the host: a release binary
    /// whose cache has never seen an image set adopts the guest runtime the
    /// installer placed beside it and assembles every launch-time piece from
    /// that archive. Each piece then resolves through the same version-keyed
    /// resolvers a launch reads, names the archive it came from, and the
    /// image set is closed to it.
    #[test]
    fn a_fresh_release_install_assembles_every_piece_from_its_own_archive() {
        use crate::guest_bins::release::{
            ReleaseGuestRuntimeOrigin, ReleaseGuestRuntimeRequest, acquire_release_guest_runtime,
        };
        const VERSION: &str = "9.9.9";
        let installed = tempfile::tempdir().unwrap();
        let archive =
            crate::guest_runtime::release_fixture::write_release_archive(installed.path(), VERSION);
        let digest = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(std::fs::read(&archive).unwrap()))
        };

        // One fresh home per architecture: a host has one.
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            let cache = tempfile::tempdir().unwrap();
            let release = acquire_release_guest_runtime(&ReleaseGuestRuntimeRequest {
                release_url: "file:///no-release-is-reachable",
                version: VERSION,
                cache_root: cache.path(),
                installed_dirs: &[installed.path().to_path_buf()],
            })
            .unwrap();
            assert_eq!(release.origin, ReleaseGuestRuntimeOrigin::Installed);
            let assembly =
                assemble_release_runtime_pieces(cache.path(), VERSION, arch, &release.archive)
                    .unwrap();
            assert_eq!(assembly.runtime.digest, digest);

            // The overlay a launch resolves is the one assembled here, and its
            // roothash is the one the host computed over its own ext4.
            let overlay = mvm_fs::overlay::RuntimeOverlayResolver::new(
                cache.path().to_path_buf(),
                VERSION.to_string(),
            )
            .resolve(&arch.to_string())
            .unwrap();
            assert_eq!(overlay.roothash, assembly.pieces.runtime_overlay.roothash);
            crate::runtime_overlay::verify_guest_runtime_overlay_verity(&overlay).unwrap();
            mvm_fs::initramfs::InitramfsResolver::new(initramfs_cache_root(cache.path()), VERSION)
                .resolve(&arch.to_string())
                .unwrap();
            for libc in SDK_SIDECAR_LIBCS {
                mvm_fs::sdk_sidecar::SdkSidecarResolver::new(
                    cache.path().to_path_buf(),
                    VERSION.to_string(),
                )
                .resolve(&arch.to_string(), libc)
                .unwrap();
            }
            assert!(
                crate::guest_agent_build::cached_guest_binaries(
                    &cache.path().join("oci"),
                    VERSION,
                    arch
                )
                .is_some(),
                "the OCI guest runtime comes from the same archive"
            );

            for piece in RuntimePiece::ALL {
                assert_eq!(
                    piece_origin(cache.path(), VERSION, arch, piece).unwrap(),
                    PieceOrigin::Archive {
                        digest: digest.clone()
                    },
                    "{}",
                    piece.label()
                );
            }
            assert_eq!(
                adopted_release_archive(cache.path(), VERSION, arch).unwrap(),
                Some(digest.clone())
            );
        }
    }

    #[test]
    fn a_release_archive_that_fails_verification_assembles_nothing_and_adopts_nothing() {
        const VERSION: &str = "9.9.9";
        let dir = tempfile::tempdir().unwrap();
        let archive = crate::guest_runtime::release_fixture::write_release_archive_tampering(
            dir.path(),
            VERSION,
            Some("x86_64/lib/musl/libmvm_host_services.so"),
        );
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;

        assert!(matches!(
            assemble_release_runtime_pieces(cache.path(), VERSION, arch, &archive),
            Err(AssembleError::GuestRuntime(_))
        ));
        assert_eq!(
            adopted_release_archive(cache.path(), VERSION, arch).unwrap(),
            None
        );
        for piece in RuntimePiece::ALL {
            assert!(
                !piece.local_image(cache.path(), VERSION, arch).exists(),
                "{}",
                piece.label()
            );
        }
        let other = tempfile::tempdir().unwrap();
        assert!(
            assemble_release_runtime_pieces(
                other.path(),
                VERSION,
                arch,
                &dir.path().join("absent")
            )
            .is_err()
        );
        assert_eq!(
            adopted_release_archive(other.path(), VERSION, arch).unwrap(),
            None
        );
    }

    #[test]
    fn an_unreadable_adoption_record_is_an_error_not_an_absence() {
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let record = release_adoption_record(cache.path(), "1.2.3", arch);
        std::fs::create_dir_all(record.parent().unwrap()).unwrap();
        std::fs::write(&record, "not a digest\n").unwrap();
        assert!(matches!(
            adopted_release_archive(cache.path(), "1.2.3", arch),
            Err(PieceOriginError::InvalidRecord { .. })
        ));
        // Another version, or the other architecture, adopted nothing.
        assert_eq!(
            adopted_release_archive(cache.path(), "1.2.4", arch).unwrap(),
            None
        );
        assert_eq!(
            adopted_release_archive(cache.path(), "1.2.3", GuestArch::Aarch64).unwrap(),
            None
        );
    }
}
