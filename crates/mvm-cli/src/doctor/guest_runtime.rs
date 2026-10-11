//! Which guest-runtime archive, or which image set, each launch-time piece in
//! the cache came from.
//!
//! The runtime overlay, the initramfs and the two SDK sidecars are assembled
//! from one guest-runtime archive in a source build, or installed from the
//! pinned image set otherwise. A bug report about a guest needs to know which,
//! and whether the pieces agree with each other and with the archive this tree
//! builds today. Read from the cache alone: nothing is built, downloaded or
//! hashed.

use mvm_build::runtime_pieces::{
    PieceOrigin, PieceOriginError, RuntimePiece, piece_origin, short_digest,
};
use mvm_client::launch::runtime_overlay::{
    RuntimeOverlayAcquireMode, runtime_overlay_acquire_mode, runtime_overlay_source_checkout_root,
};

use super::Check;

/// The archive this binary's source tree resolves to, if it has one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CurrentArchive {
    /// A release build: there is no source tree to build an archive from.
    NoSourceTree,
    /// The tree's archive has not been built into this cache.
    NotBuilt,
    Built(String),
    Unreadable(String),
}

impl CurrentArchive {
    fn detect(
        cache_root: &std::path::Path,
        version: &str,
        arch: mvm_core::arch::GuestArch,
    ) -> Self {
        let Some(workspace_root) = runtime_overlay_source_checkout_root() else {
            return Self::NoSourceTree;
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

    fn describe(&self) -> String {
        match self {
            Self::NoSourceTree => "no source archive (release build)".to_string(),
            Self::NotBuilt => "this tree's archive is not built".to_string(),
            Self::Built(digest) => format!("this tree's archive {}", short_digest(digest)),
            Self::Unreadable(error) => format!("this tree's archive unreadable: {error}"),
        }
    }

    fn digest(&self) -> Option<&str> {
        match self {
            Self::Built(digest) => Some(digest),
            _ => None,
        }
    }
}

pub(super) fn guest_runtime_check() -> Check {
    let cache_root = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir());
    let version = env!("CARGO_PKG_VERSION");
    let arch = mvm_core::arch::GuestArch::host();
    let set = mvm_build::published_image_set::SetMemberCache::locked();
    let pieces: Vec<_> = RuntimePiece::ALL
        .into_iter()
        .map(|piece| (piece, piece_origin(&cache_root, version, arch, piece, &set)))
        .collect();
    guest_runtime_line(
        &CurrentArchive::detect(&cache_root, version, arch),
        runtime_overlay_acquire_mode(),
        &mvm_core::image_set::image_train_lock()
            .image_set
            .release_tag
            .to_string(),
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
    set_tag: &str,
    pieces: &[(RuntimePiece, Result<PieceOrigin, PieceOriginError>)],
) -> Check {
    let acquisition = match mode {
        RuntimeOverlayAcquireMode::BuildFromSourceCheckout => {
            "assembled from the source guest runtime".to_string()
        }
        RuntimeOverlayAcquireMode::DownloadPublishedArtifact => {
            format!("installed from image set {set_tag}")
        }
    };
    let mut ok = true;
    let origins: Vec<String> = pieces
        .iter()
        .map(|(piece, origin)| {
            let described = match origin {
                Ok(origin) => describe_origin(origin, current.digest(), set_tag),
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

fn describe_origin(origin: &PieceOrigin, current: Option<&str>, set_tag: &str) -> String {
    match origin {
        PieceOrigin::Archive { digest } => {
            let relation = match current {
                Some(current) if current == digest => " (this tree)",
                Some(_) => " (another archive)",
                None => "",
            };
            format!("archive {}{relation}", short_digest(digest))
        }
        PieceOrigin::LocalUnrecorded => "local copy, archive not recorded".to_string(),
        PieceOrigin::ImageSet { version } => format!("image set {set_tag} (member {version})"),
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
        guest_runtime_line(&current, mode, "image-set/v9.9.9", &pieces)
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
    fn a_release_build_names_the_image_set_and_its_member_versions() {
        let member = || {
            Ok(PieceOrigin::ImageSet {
                version: "0.2.4".to_string(),
            })
        };
        let c = line(
            CurrentArchive::NoSourceTree,
            RuntimeOverlayAcquireMode::DownloadPublishedArtifact,
            [member(), member(), member(), member()],
        );
        assert!(c.ok, "{}", c.info);
        assert!(
            c.info.starts_with(
                "no source archive (release build) — installed from image set image-set/v9.9.9 — "
            ),
            "{}",
            c.info
        );
        assert_eq!(
            c.info
                .matches("image set image-set/v9.9.9 (member 0.2.4)")
                .count(),
            4,
            "{}",
            c.info
        );
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
