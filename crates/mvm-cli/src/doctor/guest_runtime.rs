//! Which guest-runtime archive each launch-time piece in the cache came from.
//!
//! The runtime overlay, the initramfs and the two SDK sidecars are assembled
//! from one guest-runtime archive: the one a source build compiles from its
//! tree, or the published one of this CLI's version — a release binary's own.
//! The image set carries none of them. A bug report about a guest needs to
//! know which archive, and whether the pieces agree with each other and with
//! it. Read from the cache alone: nothing is built, downloaded or hashed.

use mvm_build::runtime_pieces::{
    PieceOrigin, PieceOriginError, RuntimePiece, adopted_release_archive, piece_origin,
    short_digest,
};
use mvm_client::launch::runtime_overlay::{
    RuntimeOverlayAcquireMode, runtime_overlay_acquire_mode, runtime_overlay_source_checkout_root,
};

use super::Check;

/// The archive this binary's pieces should come from, if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CurrentArchive {
    /// No source tree, and no published guest runtime adopted into this
    /// cache yet.
    NoSourceTree,
    /// The tree's archive has not been built into this cache.
    NotBuilt,
    Built(String),
    /// The release guest runtime this version adopted: its archive's file
    /// name and digest.
    Release {
        name: String,
        digest: String,
    },
    Unreadable(String),
}

impl CurrentArchive {
    fn detect(
        cache_root: &std::path::Path,
        version: &str,
        arch: mvm_core::arch::GuestArch,
    ) -> Self {
        let Some(workspace_root) = runtime_overlay_source_checkout_root() else {
            return Self::release(cache_root, version, arch);
        };
        match mvm_build::guest_runtime::source_guest_runtime_digest(
            cache_root,
            version,
            arch,
            &workspace_root,
        ) {
            Ok(Some(digest)) => Self::Built(digest),
            Ok(None) => Self::NotBuilt,
            Err(error) => Self::Unreadable(error.to_string()),
        }
    }

    /// The release guest runtime this version adopted, read from its record.
    fn release(
        cache_root: &std::path::Path,
        version: &str,
        arch: mvm_core::arch::GuestArch,
    ) -> Self {
        match adopted_release_archive(cache_root, version, arch) {
            Ok(Some(digest)) => Self::Release {
                name: mvm_build::guest_bins::guest_bins_archive_name(version),
                digest,
            },
            Ok(None) => Self::NoSourceTree,
            Err(error) => Self::Unreadable(error.to_string()),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::NoSourceTree => "no source or release archive".to_string(),
            Self::NotBuilt => "this tree's archive is not built".to_string(),
            Self::Built(digest) => format!("this tree's archive {}", short_digest(digest)),
            Self::Release { name, digest } => {
                format!("release archive {name} {}", short_digest(digest))
            }
            Self::Unreadable(error) => format!("archive record unreadable: {error}"),
        }
    }

    fn digest(&self) -> Option<&str> {
        match self {
            Self::Built(digest) | Self::Release { digest, .. } => Some(digest),
            _ => None,
        }
    }

    /// What a piece assembled from this archive is called on the line.
    fn relation(&self) -> &'static str {
        match self {
            Self::Release { .. } => "this release",
            _ => "this tree",
        }
    }
}

pub(super) fn guest_runtime_check() -> Check {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let pieces: Vec<_> = RuntimePiece::ALL
        .into_iter()
        .map(|piece| (piece, piece_origin(&cache_root, version, arch, piece)))
        .collect();
    guest_runtime_line(
        &CurrentArchive::detect(&cache_root, version, arch),
        runtime_overlay_acquire_mode(),
        &pieces,
    )
}

/// `<current archive> — <acquisition> — <piece: origin; …>`, the three-segment
/// shape of the other source lines. Informational: an unreadable origin
/// record is the one failure, because something other than an assembler
/// wrote it.
fn guest_runtime_line(
    current: &CurrentArchive,
    mode: RuntimeOverlayAcquireMode,
    pieces: &[(RuntimePiece, Result<PieceOrigin, PieceOriginError>)],
) -> Check {
    let acquisition = match (mode, current) {
        (_, CurrentArchive::Release { .. }) => "assembled from the release guest runtime",
        (RuntimeOverlayAcquireMode::DownloadPublishedArtifact, CurrentArchive::NoSourceTree) => {
            "not adopted yet; `mvmctl bootstrap` assembles them from the release guest runtime"
        }
        _ => "assembled from the source guest runtime",
    };
    let mut ok = true;
    let origins: Vec<String> = pieces
        .iter()
        .map(|(piece, origin)| {
            let described = match origin {
                Ok(origin) => describe_origin(origin, current),
                Err(error) => {
                    ok = false;
                    format!("unreadable ({error})")
                }
            };
            format!("{}: {described}", piece.label())
        })
        .collect();
    Check {
        name: "guest runtime",
        category: "platform",
        ok,
        info: format!(
            "{} — {acquisition} — {}",
            current.describe(),
            origins.join("; ")
        ),
    }
}

fn describe_origin(origin: &PieceOrigin, current: &CurrentArchive) -> String {
    match origin {
        PieceOrigin::Archive { digest } => {
            let relation = match current.digest() {
                Some(expected) if expected == digest => format!(" ({})", current.relation()),
                Some(_) => " (another archive)".to_string(),
                None => String::new(),
            };
            format!("archive {}{relation}", short_digest(digest))
        }
        PieceOrigin::LocalUnrecorded => "local copy, archive not recorded".to_string(),
        PieceOrigin::Missing => "not prepared".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn line(
        current: CurrentArchive,
        mode: RuntimeOverlayAcquireMode,
        origins: [Result<PieceOrigin, PieceOriginError>; 4],
    ) -> Check {
        let pieces: Vec<_> = RuntimePiece::ALL.into_iter().zip(origins).collect();
        guest_runtime_line(&current, mode, &pieces)
    }

    #[test]
    fn a_source_build_names_the_archive_each_piece_came_from() {
        let c = line(
            CurrentArchive::Built(digest('a')),
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
            [
                Ok(PieceOrigin::Archive {
                    digest: digest('a'),
                }),
                Ok(PieceOrigin::Archive {
                    digest: digest('a'),
                }),
                Ok(PieceOrigin::Archive {
                    digest: digest('b'),
                }),
                Ok(PieceOrigin::Missing),
            ],
        );
        assert!(c.ok, "{}", c.info);
        assert_eq!(c.name, "guest runtime");
        assert_eq!(c.info.matches(" — ").count(), 2, "{}", c.info);
        assert!(
            c.info.starts_with("this tree's archive aaaaaaaaaaaa — "),
            "{}",
            c.info
        );
        assert!(
            c.info
                .contains("runtime overlay: archive aaaaaaaaaaaa (this tree)"),
            "{}",
            c.info
        );
        assert!(
            c.info
                .contains("initramfs: archive aaaaaaaaaaaa (this tree)"),
            "{}",
            c.info
        );
        assert!(
            c.info
                .contains("SDK sidecar glibc: archive bbbbbbbbbbbb (another archive)"),
            "{}",
            c.info
        );
        assert!(
            c.info.contains("SDK sidecar musl: not prepared"),
            "{}",
            c.info
        );
    }

    #[test]
    fn a_release_build_names_the_release_archive_each_piece_came_from() {
        let archive = || {
            Ok(PieceOrigin::Archive {
                digest: digest('c'),
            })
        };
        let c = line(
            CurrentArchive::Release {
                name: "mvm-guest-bins-v9.9.9.tar.gz".to_string(),
                digest: digest('c'),
            },
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
            [archive(), archive(), archive(), archive()],
        );
        assert!(c.ok, "{}", c.info);
        assert_eq!(c.info.matches(" — ").count(), 2, "{}", c.info);
        assert!(
            c.info.starts_with(
                "release archive mvm-guest-bins-v9.9.9.tar.gz cccccccccccc — \
                 assembled from the release guest runtime — "
            ),
            "{}",
            c.info
        );
        assert_eq!(
            c.info
                .matches("archive cccccccccccc (this release)")
                .count(),
            4,
            "{}",
            c.info
        );
        assert!(!c.info.contains("image set"), "{}", c.info);
    }

    /// An adoption record lies only about the cache it is in, so the live
    /// check reads it: a release binary's line names the archive it adopted.
    #[test]
    fn an_adopted_release_archive_is_read_from_its_record() {
        let cache = tempfile::tempdir().unwrap();
        let arch = mvm_core::arch::GuestArch::X86_64;
        assert_eq!(
            CurrentArchive::release(cache.path(), "9.9.9", arch),
            CurrentArchive::NoSourceTree
        );
        let record =
            mvm_build::runtime_pieces::release_adoption_record(cache.path(), "9.9.9", arch);
        std::fs::create_dir_all(record.parent().unwrap()).unwrap();
        std::fs::write(&record, format!("{}\n", digest('c'))).unwrap();
        assert_eq!(
            CurrentArchive::release(cache.path(), "9.9.9", arch),
            CurrentArchive::Release {
                name: "mvm-guest-bins-v9.9.9.tar.gz".to_string(),
                digest: digest('c'),
            }
        );
        std::fs::write(&record, "garbage\n").unwrap();
        assert!(matches!(
            CurrentArchive::release(cache.path(), "9.9.9", arch),
            CurrentArchive::Unreadable(_)
        ));
    }

    /// A cache an older CLI populated from the image set reports nothing
    /// prepared: those copies are not this CLI's pieces, and the line names
    /// the bootstrap that assembles them instead of the image set.
    #[test]
    fn a_published_build_that_has_not_bootstrapped_names_bootstrap_not_the_image_set() {
        let c = line(
            CurrentArchive::NoSourceTree,
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
            [
                Ok(PieceOrigin::Missing),
                Ok(PieceOrigin::Missing),
                Ok(PieceOrigin::Missing),
                Ok(PieceOrigin::Missing),
            ],
        );
        assert!(c.ok, "{}", c.info);
        assert!(
            c.info.starts_with(
                "no source or release archive — not adopted yet; `mvmctl bootstrap` assembles \
                 them from the release guest runtime — "
            ),
            "{}",
            c.info
        );
        assert!(!c.info.contains("image set"), "{}", c.info);
    }

    #[test]
    fn an_unrecorded_local_copy_is_reported_rather_than_attributed() {
        let c = line(
            CurrentArchive::NotBuilt,
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
            [
                Ok(PieceOrigin::LocalUnrecorded),
                Ok(PieceOrigin::Missing),
                Ok(PieceOrigin::Missing),
                Ok(PieceOrigin::Missing),
            ],
        );
        assert!(c.ok);
        assert!(
            c.info
                .contains("runtime overlay: local copy, archive not recorded"),
            "{}",
            c.info
        );
        assert!(
            c.info.starts_with("this tree's archive is not built — "),
            "{}",
            c.info
        );
    }

    #[test]
    fn an_unreadable_origin_record_fails_the_check() {
        let c = line(
            CurrentArchive::Built(digest('a')),
            RuntimeOverlayAcquireMode::BuildFromSourceCheckout,
            [
                Ok(PieceOrigin::Missing),
                Err(PieceOriginError::InvalidRecord {
                    path: "/cache/initramfs/1.2.3/x86_64/GUEST_RUNTIME_ARCHIVE".into(),
                }),
                Ok(PieceOrigin::Missing),
                Ok(PieceOrigin::Missing),
            ],
        );
        assert!(!c.ok);
        assert!(c.info.contains("initramfs: unreadable"), "{}", c.info);
        assert_eq!(c.info.matches(" — ").count(), 2, "{}", c.info);
    }

    /// The live check reads the real cache under an isolated home: with
    /// nothing prepared, every piece says so and nothing is built.
    #[test]
    fn the_live_check_reports_an_empty_cache_without_building() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().unwrap();
        env.isolate_mvm_home(home.path());
        let c = guest_runtime_check();
        assert!(c.ok, "{}", c.info);
        for piece in RuntimePiece::ALL {
            assert!(
                c.info.contains(&format!("{}: not prepared", piece.label())),
                "{}",
                c.info
            );
        }
        assert!(!home.path().join("cache/guest-runtime").exists());
    }
}
