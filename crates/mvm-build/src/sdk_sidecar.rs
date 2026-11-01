//! Fetch, verify, and install the published SDK-sidecar artifact.
//!
//! Picking a cached sidecar and proving it sound is the resolve half and lives
//! in [`mvm_fs::sdk_sidecar`]. This module owns how one *lands* in the cache:
//! host-side ext4 packing from the verified guest runtime for a source
//! checkout, or the per-arch, per-libc member of the signed image set this
//! build pins. Both use the same stage-then-rename cache discipline.
//!
//! Every step fails closed. A set that does not declare the member, a size or
//! digest mismatch, an unsafe archive entry, an inner-manifest disagreement, or
//! a post-install resolve failure all return `Err` and leave the cache
//! untouched. There is no degraded install, because a workload admitted to call
//! an SDK-served host service that boots without the cdylib hits an in-guest
//! `dlopen` failure it cannot act on.

use std::path::{Path, PathBuf};

use crate::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use thiserror::Error;

use crate::runtime_overlay::RuntimeOverlayError;

use mvm_fs::overlay::CHECKSUM_MANIFEST_FILE;
use mvm_fs::sdk_sidecar::{
    SDK_SIDECAR_IMAGE_FILE, SDK_SIDECAR_VERSION_FILE, SdkSidecarArtifact, SdkSidecarError,
    SdkSidecarLayout, SdkSidecarResolver, verify_sidecar_dir_integrity,
};

/// The per-architecture, per-libc release filenames the SDK sidecar is
/// published under.
///
/// A constructor rather than a `format!` at each call site so the release
/// workflow's asset names have exactly one Rust-side definition to be asserted
/// against — a drift between the two is otherwise invisible until an end-user's
/// download 404s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdkSidecarArtifactNames {
    /// The release tarball name.
    pub archive: String,
    /// The tarball's sha256 checksum sidecar name.
    pub archive_checksum: String,
}

impl SdkSidecarArtifactNames {
    /// Compute the release filenames for `arch` and `libc`, using the same
    /// directory-name segments as the cache layout. Both dimensions are in the
    /// filename so a verified archive cannot be installed under the wrong
    /// libc key while still appearing authentic.
    #[must_use]
    pub fn for_target(arch: &str, libc: GuestLibc) -> Self {
        Self {
            archive: format!("sdk-sidecar-{arch}-{libc}.tar.gz"),
            archive_checksum: format!("sdk-sidecar-{arch}-{libc}.tar.gz.sha256"),
        }
    }
}

/// Exactly the members the sidecar's release tarball may carry: the three files
/// [`SdkSidecarResolver::resolve`] verifies, and nothing else. Doubles as the
/// extraction allow-list, the completeness check, and the install file set, so
/// the transport can neither widen nor narrow what the resolver will check.
const SIDECAR_ARCHIVE_MEMBERS: [&str; 3] = [
    SDK_SIDECAR_IMAGE_FILE,
    SDK_SIDECAR_VERSION_FILE,
    CHECKSUM_MANIFEST_FILE,
];

/// Failure acquiring or installing a published SDK-sidecar artifact.
#[derive(Debug, Error)]
pub enum SdkSidecarBuildError {
    /// The resolve half rejected the artifact: missing files, version drift,
    /// manifest mismatch, or a payload carrying no cdylib. Raised both for a
    /// cache miss and — deliberately — for the post-install re-verification.
    #[error(transparent)]
    Resolve(#[from] SdkSidecarError),

    /// Fetching, integrity-checking, or safely extracting the published archive
    /// failed. Shares the release-transport error type with the runtime overlay
    /// because both go through one downloader and one extraction guard.
    #[error(transparent)]
    Transport(#[from] RuntimeOverlayError),

    /// An io failure while staging or installing, naming the operation and
    /// the path it failed on.
    #[error("{op} {}: {source}", .path.display())]
    Io {
        /// What was being done: "copying", "renaming", ...
        op: &'static str,
        /// The path the operation failed on.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: std::io::Error,
    },

    /// The computed cache path or the staged file set was not usable.
    #[error("SDK sidecar install invalid: {reason}")]
    InstallInvalid {
        /// Human-readable description of the problem.
        reason: String,
    },

    /// The cdylib's source inputs could not be fingerprinted, so the cached
    /// sidecar's provenance is unknown. Distinct from a resolve failure: the
    /// artifact may be perfectly sound and only the *working tree* unreadable.
    #[error("SDK sidecar source fingerprint failed: {reason}")]
    FingerprintFailed {
        /// Human-readable description of the problem.
        reason: String,
    },

    /// An indeterminate libc cannot select a published artifact safely.
    #[error("cannot select a published SDK sidecar for unknown libc on {arch}")]
    UnknownLibc {
        /// The architecture whose image did not identify its libc.
        arch: GuestArch,
    },
}

/// Map an io failure on `path` into [`SdkSidecarBuildError::Io`].
fn io_at(op: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> SdkSidecarBuildError {
    let path = path.to_path_buf();
    move |source| SdkSidecarBuildError::Io { op, path, source }
}

/// A fresh temporary directory, its failure naming where it was being made.
fn temp_dir() -> Result<tempfile::TempDir, SdkSidecarBuildError> {
    tempfile::tempdir().map_err(io_at(
        "creating a temporary directory in",
        &std::env::temp_dir(),
    ))
}

/// Install an authenticated SDK-sidecar archive published per CLI version:
/// safely extract it, re-check it against its own manifest, install it under
/// `version`, and resolve the installed entry expecting `version`.
///
/// The caller must have authenticated `archive` already — an unauthenticated
/// tar is never parsed.
pub fn install_sdk_sidecar_archive(
    archive: &Path,
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
    cache_root: &Path,
) -> Result<SdkSidecarArtifact, SdkSidecarBuildError> {
    let arch_dir = arch.to_string();
    let tmp = temp_dir()?;
    let extracted = extract_sidecar_archive(archive, tmp.path())?;
    install_sidecar_into_cache(&extracted, cache_root, version, &arch_dir, libc)?;

    Ok(
        SdkSidecarResolver::new(cache_root.to_path_buf(), version.to_string())
            .resolve(&arch_dir, libc)?,
    )
}

/// Extract an authenticated sidecar archive into `<scratch>/extracted` and
/// re-check it against the manifest it carries.
fn extract_sidecar_archive(
    archive: &Path,
    scratch: &Path,
) -> Result<PathBuf, SdkSidecarBuildError> {
    let extracted = scratch.join("extracted");
    std::fs::create_dir(&extracted).map_err(io_at("creating", &extracted))?;
    crate::runtime_overlay::extract_release_archive(archive, &extracted, &SIDECAR_ARCHIVE_MEMBERS)?;
    verify_sidecar_dir_integrity(&extracted)?;
    Ok(extracted)
}

/// Install a verified sidecar artifact directory into the canonical cache
/// layout, replacing any existing entry for `(version, arch)` wholesale.
///
/// Staging and promotion are separate steps: a crash before the rename leaves
/// only a `<arch>.tmp.<pid>/` directory that a later install reaps, never a
/// half-written entry a resolver could pick up.
pub fn install_sidecar_into_cache(
    source: &Path,
    cache_root: &Path,
    version: &str,
    arch: &str,
    libc: GuestLibc,
) -> Result<SdkSidecarLayout, SdkSidecarBuildError> {
    install_sidecar_with_markers(source, cache_root, version, arch, libc, &[])
}

/// Install a sidecar produced from the current checkout and publish its source
/// fingerprint in the same staging rename as the verified artifact files.
///
/// The marker is part of the promotion boundary: a concurrent resolver can
/// observe either the previous cache entry or the complete new entry, never a
/// source-built image temporarily mislabeled as a published artifact.
pub fn install_source_built_sidecar(
    source: &Path,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
    fingerprint: &str,
) -> Result<SdkSidecarArtifact, SdkSidecarBuildError> {
    install_source_built_sidecar_from(source, cache_root, version, arch, libc, fingerprint, None)
}

/// [`install_source_built_sidecar`], also recording the guest-runtime archive
/// the sidecar was packed from inside the same staging rename.
fn install_source_built_sidecar_from(
    source: &Path,
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
    fingerprint: &str,
    archive_digest: Option<&str>,
) -> Result<SdkSidecarArtifact, SdkSidecarBuildError> {
    if fingerprint.trim().is_empty() {
        return Err(SdkSidecarBuildError::InstallInvalid {
            reason: "source fingerprint is empty".to_string(),
        });
    }
    require_canonical_sidecar_files(source)?;
    verify_sidecar_dir_integrity(source)?;
    let version_path = source.join(SDK_SIDECAR_VERSION_FILE);
    let produced_version =
        std::fs::read_to_string(&version_path).map_err(io_at("reading", &version_path))?;
    if produced_version.trim() != version {
        return Err(SdkSidecarBuildError::InstallInvalid {
            reason: format!(
                "source-built sidecar VERSION {:?} does not match expected {version:?}",
                produced_version.trim()
            ),
        });
    }
    let arch_dir = arch.to_string();
    let mut markers = vec![(LOCAL_SOURCE_FINGERPRINT_FILE, fingerprint.trim())];
    if let Some(digest) = archive_digest {
        if !crate::guest_runtime::is_archive_digest(digest) {
            return Err(SdkSidecarBuildError::InstallInvalid {
                reason: format!("{digest:?} is not a guest-runtime archive digest"),
            });
        }
        markers.push((crate::runtime_pieces::ARCHIVE_ORIGIN_FILE, digest));
    }
    install_sidecar_with_markers(source, cache_root, version, &arch_dir, libc, &markers)?;
    Ok(
        SdkSidecarResolver::new(cache_root.to_path_buf(), version.to_string())
            .resolve(&arch_dir, libc)?,
    )
}

/// Build the libc-specific SDK sidecar from a verified guest-runtime member.
/// The image contains only the host-services cdylib: the guest workload's own
/// dynamic loader and libc satisfy its dependencies.
///
/// The installed sidecar is stamped with the archive's recorded cdylib source
/// fingerprint — the inputs its one file was compiled from — so a later archive
/// that rebuilt only other guest binaries reuses it, and
/// [`cached_sidecar_provenance`] can tell whether it carries this checkout's
/// host-services sources. It also records the archive digest it was packed
/// from ([`crate::runtime_pieces::ARCHIVE_ORIGIN_FILE`]); a reused sidecar
/// keeps naming the archive whose member it carries.
pub fn build_sdk_sidecar_from_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
    runtime: &crate::guest_runtime::GuestRuntime,
) -> Result<SdkSidecarArtifact, SdkSidecarBuildError> {
    if libc == GuestLibc::Unknown {
        return Err(SdkSidecarBuildError::UnknownLibc { arch });
    }
    if runtime.manifest.version != version {
        return Err(SdkSidecarBuildError::InstallInvalid {
            reason: format!(
                "guest runtime version {} does not match sidecar version {version}",
                runtime.manifest.version
            ),
        });
    }
    let member = format!("{arch}/lib/{libc}/libmvm_host_services.so");
    let Some(expected_digest) = runtime.manifest.files.get(&member) else {
        return Err(SdkSidecarBuildError::InstallInvalid {
            reason: format!("guest runtime manifest does not contain {member}"),
        });
    };
    let source = runtime.root.join(&member);
    if !std::fs::symlink_metadata(&source).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err(SdkSidecarBuildError::InstallInvalid {
            reason: format!("guest runtime member is not a regular file: {member}"),
        });
    }
    let cdylib = std::fs::read(&source).map_err(io_at("reading", &source))?;
    use sha2::Digest as _;
    if hex::encode(sha2::Sha256::digest(&cdylib)) != *expected_digest {
        return Err(SdkSidecarBuildError::InstallInvalid {
            reason: format!("guest runtime member changed while packing: {member}"),
        });
    }
    let source_fingerprint = runtime.manifest.sdk_cdylib_source_fingerprint.as_str();
    let resolver = SdkSidecarResolver::new(cache_root.to_path_buf(), version.to_string());
    let layout = resolver.layout(&arch.to_string(), libc);
    if std::fs::read_to_string(layout.artifact_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE))
        .is_ok_and(|fingerprint| fingerprint.trim() == source_fingerprint)
        && let Ok(cached) = resolver.resolve(&arch.to_string(), libc)
    {
        return Ok(cached);
    }
    let image = mvm_fs::ext4::build_image(
        vec![
            mvm_fs::ext4::Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
                owner: mvm_fs::ext4::Owner::ROOT,
            },
            mvm_fs::ext4::Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: cdylib,
                xattrs: Vec::new(),
                owner: mvm_fs::ext4::Owner::ROOT,
            },
        ],
        &Default::default(),
    )
    .map_err(|e| SdkSidecarBuildError::InstallInvalid {
        reason: format!("build SDK sidecar ext4: {e}"),
    })?;
    let staging = temp_dir()?;
    let image_path = staging.path().join(SDK_SIDECAR_IMAGE_FILE);
    let version_path = staging.path().join(SDK_SIDECAR_VERSION_FILE);
    std::fs::write(&image_path, &image).map_err(io_at("writing", &image_path))?;
    std::fs::write(&version_path, format!("{version}\n"))
        .map_err(io_at("writing", &version_path))?;
    let manifest_path = staging.path().join(CHECKSUM_MANIFEST_FILE);
    let body = format!(
        "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
        hex::encode(sha2::Sha256::digest(&image)),
        hex::encode(sha2::Sha256::digest(format!("{version}\n").as_bytes())),
    );
    std::fs::write(&manifest_path, body).map_err(io_at("writing", &manifest_path))?;
    install_source_built_sidecar_from(
        staging.path(),
        cache_root,
        version,
        arch,
        libc,
        source_fingerprint,
        Some(&runtime.digest),
    )
}

/// Refuse a source directory that does not hold the canonical file set,
/// naming the first missing path. The integrity check below reads these files
/// by their canonical names and would otherwise surface a bare `ENOENT` with
/// no path — which is how a directory holding the files under other names
/// (a pair cache entry, whose files carry the producer's manifest names)
/// reads to an operator.
fn require_canonical_sidecar_files(source: &Path) -> Result<(), SdkSidecarBuildError> {
    for name in SIDECAR_ARCHIVE_MEMBERS {
        let path = source.join(name);
        if !path.is_file() {
            return Err(SdkSidecarBuildError::InstallInvalid {
                reason: format!(
                    "source-built sidecar directory {} has no {name} (expected {})",
                    source.display(),
                    path.display()
                ),
            });
        }
    }
    Ok(())
}

/// Install `source`'s canonical files, plus each `(file name, value)` marker,
/// as one staged directory published by a single rename.
fn install_sidecar_with_markers(
    source: &Path,
    cache_root: &Path,
    version: &str,
    arch: &str,
    libc: GuestLibc,
    markers: &[(&str, &str)],
) -> Result<SdkSidecarLayout, SdkSidecarBuildError> {
    let layout = SdkSidecarLayout::under(cache_root, version, arch, libc);
    let parent =
        layout
            .artifact_dir
            .parent()
            .ok_or_else(|| SdkSidecarBuildError::InstallInvalid {
                reason: format!(
                    "computed artifact dir {} has no parent",
                    layout.artifact_dir.display()
                ),
            })?;
    std::fs::create_dir_all(parent).map_err(io_at("creating", parent))?;
    let staging = stage_sidecar_artifact(parent, arch, source)?;
    for (name, value) in markers {
        let marker = staging.join(name);
        std::fs::write(&marker, format!("{value}\n")).map_err(io_at("writing", &marker))?;
        crate::runtime_overlay::set_cache_perms(&marker)?;
    }
    promote_staging(&staging, &layout.artifact_dir)?;
    Ok(layout)
}

/// Copy the canonical file set into a sibling staging directory, leaving it
/// unpublished. Split from [`promote_staging`] so the window a crash can land
/// in is a real boundary a test can stop inside.
fn stage_sidecar_artifact(
    parent: &Path,
    arch: &str,
    source: &Path,
) -> Result<PathBuf, SdkSidecarBuildError> {
    let staging = parent.join(crate::cache_install::staging_dir_name(arch));
    // A previous interrupted install of our own pid would otherwise be merged
    // into rather than replaced.
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(io_at("removing", &staging))?;
    }
    // A run killed before its rename orphans a staging dir under another pid
    // that nothing else would ever clean up.
    crate::cache_install::reap_stale_staging(parent, arch);
    std::fs::create_dir(&staging).map_err(io_at("creating", &staging))?;

    for name in SIDECAR_ARCHIVE_MEMBERS {
        let from = source.join(name);
        if !from.is_file() {
            return Err(SdkSidecarBuildError::InstallInvalid {
                reason: format!("verified sidecar source is missing {name}"),
            });
        }
        let to = staging.join(name);
        std::fs::copy(&from, &to).map_err(io_at("copying", &from))?;
        crate::runtime_overlay::set_cache_perms(&to)?;
    }
    Ok(staging)
}

/// Publish a staged artifact directory at `artifact_dir`.
///
/// Two-phase (remove then rename) rather than strictly atomic: the only window
/// in which the cache lacks a complete entry is microsecond-scale, and the
/// resolver re-reads on every launch anyway.
fn promote_staging(staging: &Path, artifact_dir: &Path) -> Result<(), SdkSidecarBuildError> {
    if artifact_dir.exists() {
        std::fs::remove_dir_all(artifact_dir).map_err(io_at("removing", artifact_dir))?;
    }
    std::fs::rename(staging, artifact_dir)
        .map_err(io_at("renaming the staged sidecar into", artifact_dir))?;
    Ok(())
}

/// Name of the marker recording which source tree built a cached sidecar.
///
/// Absent on a downloaded artifact, which is correct and load-bearing: absence
/// is how a published sidecar is told apart from a source-built one.
pub const LOCAL_SOURCE_FINGERPRINT_FILE: &str = "SOURCE_FINGERPRINT";

/// What a cached sidecar was built from, relative to the working tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarProvenance {
    /// Built from this exact source tree.
    MatchesSource,
    /// Built from a different revision of this source tree.
    StaleSource,
    /// The published artifact. It cannot carry local changes to the cdylib,
    /// because nothing local produced it.
    Published,
}

/// Record which source tree produced the sidecar now in the cache.
///
/// The source-build install path records the marker inside its atomic staging
/// boundary. This helper remains useful to provenance tooling and tests that
/// need to label an already-staged fixture.
pub fn record_source_fingerprint(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
    fingerprint: &str,
) -> std::io::Result<()> {
    let layout = SdkSidecarLayout::under(cache_root, version, &arch.to_string(), libc);
    std::fs::create_dir_all(&layout.artifact_dir)?;
    std::fs::write(
        layout.artifact_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE),
        format!("{fingerprint}\n"),
    )
}

/// Compare the cached sidecar against `workspace_root`'s cdylib sources.
///
/// Published sidecars are cached under `<version>/<arch>`. That key does not
/// move when someone edits the cdylib, so provenance distinguishes a release
/// artifact from a sidecar explicitly built from this checkout and detects
/// when the latter no longer matches its source inputs.
pub fn cached_sidecar_provenance(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
    workspace_root: &Path,
) -> Result<SidecarProvenance, SdkSidecarBuildError> {
    let layout = SdkSidecarLayout::under(cache_root, version, &arch.to_string(), libc);
    let recorded = std::fs::read_to_string(layout.artifact_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE));
    let Ok(recorded) = recorded else {
        return Ok(SidecarProvenance::Published);
    };
    let expected = crate::guest_agent_build::sdk_cdylib_source_fingerprint(workspace_root)
        .map_err(|e| SdkSidecarBuildError::FingerprintFailed {
            reason: format!("compute SDK cdylib source fingerprint: {e}"),
        })?;
    Ok(if recorded.trim() == expected {
        SidecarProvenance::MatchesSource
    } else {
        SidecarProvenance::StaleSource
    })
}

/// Resolve `arch`'s sidecar from `resolver`'s cache; on a miss with a
/// non-default cache root (a worktree-isolated `MVM_HOME`), seed that cache from
/// the default one and retry once.
///
/// Still a pure cache operation — no network, no build. A default-cache miss
/// surfaces the original resolve error unchanged.
pub fn resolve_or_seed_from_default_cache(
    resolver: &SdkSidecarResolver,
    arch: GuestArch,
    libc: GuestLibc,
) -> Result<SdkSidecarArtifact, SdkSidecarBuildError> {
    let arch_dir = arch.to_string();
    match resolver.resolve(&arch_dir, libc) {
        Ok(artifact) => Ok(artifact),
        Err(initial_error) => {
            if seed_from_default_cache(resolver, &arch_dir, libc)? {
                return Ok(resolver.resolve(&arch_dir, libc)?);
            }
            Err(initial_error.into())
        }
    }
}

fn seed_from_default_cache(
    resolver: &SdkSidecarResolver,
    arch_dir: &str,
    libc: GuestLibc,
) -> Result<bool, SdkSidecarBuildError> {
    let version = resolver.expected_version().to_string();
    let target_root = resolver.cache_root().to_path_buf();
    crate::cache_install::seed_on_miss(
        resolver.cache_root(),
        &crate::cache_install::default_cache_root(),
        |root| {
            SdkSidecarResolver::new(root.to_path_buf(), version.clone())
                .resolve(arch_dir, libc)
                .ok()
                .map(|artifact| {
                    SdkSidecarLayout::under(root, &artifact.version, &artifact.arch, artifact.libc)
                })
        },
        |source| {
            install_sidecar_into_cache(
                &source.artifact_dir,
                &target_root,
                &source.version,
                &source.arch,
                source.libc,
            )
            .map(|_| ())
        },
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    const FIXTURE_VERSION: &str = "9.9.9";

    /// A verified guest runtime under `source` holding one host-services
    /// object per libc, recording `cdylib_fingerprint` as its cdylib sources.
    fn sidecar_runtime(
        source: &Path,
        arch: GuestArch,
        cdylib_fingerprint: &str,
    ) -> crate::guest_runtime::GuestRuntime {
        use mvm_core::image_set::{GitCommit, WorktreeState};
        let mut files = std::collections::BTreeMap::new();
        for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
            let member = format!("{arch}/lib/{libc}/libmvm_host_services.so");
            let bytes = mvm_fs::elf::test_fixture::shared_object(&[
                "libgcc_s.so.1",
                libc.libc_soname().unwrap(),
            ]);
            let path = source.join(&member);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &bytes).unwrap();
            files.insert(member, sha256_hex(&bytes));
        }
        crate::guest_runtime::GuestRuntime {
            root: source.to_path_buf(),
            digest: "d".repeat(64),
            release_proof: None,
            manifest: crate::guest_bins::GuestBinsManifest {
                schema_version: crate::guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
                version: FIXTURE_VERSION.into(),
                guest_source_fingerprint: "g".repeat(64),
                sdk_cdylib_source_fingerprint: cdylib_fingerprint.to_string(),
                source: crate::image_source::RepoIdentity {
                    commit: GitCommit::new("a".repeat(40)).unwrap(),
                    worktree: WorktreeState::Clean,
                },
                files,
                assemblies: Default::default(),
            },
        }
    }

    /// The explicit verb and bootstrap pack both variants through
    /// `pack_sdk_sidecars`. Each records the archive it was packed from, and a
    /// later archive with the same host-services sources reuses the sidecar
    /// without relabelling it.
    #[test]
    fn packed_sidecars_record_the_archive_they_came_from() {
        use crate::runtime_pieces::{
            PieceOrigin, RuntimePiece, SDK_SIDECAR_LIBCS, pack_sdk_sidecars, piece_origin,
        };
        let source = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let mut runtime = sidecar_runtime(source.path(), arch, &"s".repeat(64));

        let packed = pack_sdk_sidecars(cache.path(), FIXTURE_VERSION, arch, &runtime).unwrap();
        assert_eq!(
            packed.iter().map(|a| a.libc).collect::<Vec<_>>(),
            SDK_SIDECAR_LIBCS
        );
        let origin = |libc| {
            piece_origin(
                cache.path(),
                FIXTURE_VERSION,
                arch,
                RuntimePiece::SdkSidecar(libc),
            )
            .unwrap()
        };
        for libc in SDK_SIDECAR_LIBCS {
            assert_eq!(
                origin(libc),
                PieceOrigin::Archive {
                    digest: "d".repeat(64)
                }
            );
        }

        runtime.digest = "e".repeat(64);
        pack_sdk_sidecars(cache.path(), FIXTURE_VERSION, arch, &runtime).unwrap();
        for libc in SDK_SIDECAR_LIBCS {
            assert_eq!(
                origin(libc),
                PieceOrigin::Archive {
                    digest: "d".repeat(64)
                },
                "a reused sidecar still names the archive its bytes came from"
            );
        }
    }

    #[test]
    fn guest_runtime_sidecar_packs_one_cdylib_for_each_libc_and_rejects_bad_members() {
        let source = tempfile::tempdir().unwrap();
        let cache = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        let mut runtime = sidecar_runtime(source.path(), arch, &"s".repeat(64));
        for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
            let artifact = build_sdk_sidecar_from_guest_runtime(
                cache.path(),
                FIXTURE_VERSION,
                arch,
                libc,
                &runtime,
            )
            .unwrap();
            let fs = ext4_view::Ext4::load_from_path(&artifact.image).unwrap();
            let names: Vec<Vec<u8>> = fs
                .read_dir("/lib")
                .unwrap()
                .map(|entry| entry.unwrap().file_name().as_ref().to_vec())
                .filter(|name| name != b"." && name != b"..")
                .collect();
            assert_eq!(names, vec![b"libmvm_host_services.so".to_vec()]);
            assert_eq!(artifact.libc, libc);
        }
        let member = format!("{arch}/lib/musl/libmvm_host_services.so");
        let digest = runtime.manifest.files.remove(&member).unwrap();
        let error = build_sdk_sidecar_from_guest_runtime(
            cache.path(),
            FIXTURE_VERSION,
            arch,
            GuestLibc::Musl,
            &runtime,
        )
        .unwrap_err();
        assert!(error.to_string().contains(&member), "{error}");
        runtime.manifest.files.insert(member.clone(), digest);
        std::fs::write(source.path().join(&member), b"changed").unwrap();
        let error = build_sdk_sidecar_from_guest_runtime(
            cache.path(),
            FIXTURE_VERSION,
            arch,
            GuestLibc::Musl,
            &runtime,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("changed while packing"),
            "{error}"
        );
        assert!(matches!(
            build_sdk_sidecar_from_guest_runtime(
                cache.path(),
                FIXTURE_VERSION,
                arch,
                GuestLibc::Unknown,
                &runtime
            ),
            Err(SdkSidecarBuildError::UnknownLibc { .. })
        ));
    }

    use mvm_contract::hash::sha256_hex;

    /// A minimal sidecar ext4 carrying the one path the resolver proves present,
    /// built with the in-repo pure-Rust writer so the fixture needs no `mkfs`.
    ///
    /// `libc` is explicit at every call site rather than defaulted, because the
    /// resolver proves an artifact's libc from the object's own `DT_NEEDED` and
    /// refuses one that disagrees with the slot it was filed under. A default
    /// here would let a fixture disagree with its own slot silently — the exact
    /// mistake the check exists to catch.
    fn sidecar_ext4_bytes(libc: GuestLibc) -> Vec<u8> {
        use mvm_fs::ext4::{Node, Owner};
        let nodes = vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            },
            Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: mvm_fs::elf::test_fixture::shared_object(&[
                    "libgcc_s.so.1",
                    libc.libc_soname().expect("a fixture names a real libc"),
                ]),
                xattrs: Vec::new(),
                owner: Owner::ROOT,
            },
        ];
        mvm_fs::ext4::build_image(nodes, &Default::default())
            .expect("build the sidecar ext4 fixture")
    }

    fn stage_sidecar_dir(root: &Path, version: &str, image: &[u8]) {
        let version = format!("{version}\n");
        std::fs::write(root.join(SDK_SIDECAR_IMAGE_FILE), image).unwrap();
        std::fs::write(root.join(SDK_SIDECAR_VERSION_FILE), &version).unwrap();
        std::fs::write(
            root.join(CHECKSUM_MANIFEST_FILE),
            format!(
                "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
                sha256_hex(image),
                sha256_hex(version.as_bytes()),
            ),
        )
        .unwrap();
    }

    /// A workspace shaped like the ones `sdk_cdylib_source_fingerprint` reads.
    fn fake_checkout(root: &Path, sdk_src: &str) {
        for rel in [
            "crates/mvm-contract/src",
            "crates/mvm-core/src",
            "crates/mvm-agentd/src",
            "crates/mvm-host-services/src",
            "crates/mvm-setpriv/src",
        ] {
            std::fs::create_dir_all(root.join(rel)).unwrap();
            std::fs::write(root.join(rel).join("lib.rs"), "pub fn shared() {}\n").unwrap();
        }
        for rel in [
            "Cargo.lock",
            "Cargo.toml",
            "crates/mvm-contract/Cargo.toml",
            "crates/mvm-core/Cargo.toml",
            "crates/mvm-agentd/Cargo.toml",
            "crates/mvm-host-services/Cargo.toml",
            "crates/mvm-setpriv/Cargo.toml",
        ] {
            std::fs::write(root.join(rel), "[package]\n").unwrap();
        }
        std::fs::write(root.join("crates/mvm-host-services/src/lib.rs"), sdk_src).unwrap();
    }

    /// The sidecar the bootstrap packs from this checkout's guest runtime is
    /// recognised as this checkout's: the provenance check and the producer
    /// agree on what the marker records. A sidecar stamped with anything else
    /// would warn on every launch that it predates the tree.
    #[test]
    fn a_sidecar_packed_from_the_guest_runtime_matches_its_checkout() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let checkout = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        fake_checkout(checkout.path(), "// v1\n");
        let fingerprint =
            crate::guest_agent_build::sdk_cdylib_source_fingerprint(checkout.path()).unwrap();
        let arch = GuestArch::host();
        let mut runtime = sidecar_runtime(source.path(), arch, &fingerprint);
        let provenance = |tree: &Path| {
            cached_sidecar_provenance(cache.path(), FIXTURE_VERSION, arch, GuestLibc::Musl, tree)
                .unwrap()
        };

        let first = build_sdk_sidecar_from_guest_runtime(
            cache.path(),
            FIXTURE_VERSION,
            arch,
            GuestLibc::Musl,
            &runtime,
        )
        .unwrap();
        assert_eq!(
            provenance(checkout.path()),
            SidecarProvenance::MatchesSource
        );

        // An archive that rebuilt only other guest binaries carries the same
        // cdylib sources, so the packed sidecar is reused rather than rewritten.
        // Its cdylib bytes differ too, so a repack would change the image.
        runtime.digest = "e".repeat(64);
        let member = format!("{arch}/lib/musl/libmvm_host_services.so");
        let rebuilt =
            mvm_fs::elf::test_fixture::shared_object(&["libgcc_s.so.1", "libm.so", "libc.so"]);
        std::fs::write(source.path().join(&member), &rebuilt).unwrap();
        runtime.manifest.files.insert(member, sha256_hex(&rebuilt));
        let reused = build_sdk_sidecar_from_guest_runtime(
            cache.path(),
            FIXTURE_VERSION,
            arch,
            GuestLibc::Musl,
            &runtime,
        )
        .unwrap();
        assert_eq!(reused.image_sha256, first.image_sha256);

        // A checkout whose host-services sources moved on, as the next process
        // sees it (one process answers a tree's fingerprint once).
        let edited = tempfile::tempdir().unwrap();
        fake_checkout(edited.path(), "// v2\n");
        assert_eq!(provenance(edited.path()), SidecarProvenance::StaleSource);
    }

    /// A downloaded sidecar carries no source marker, and that absence is the
    /// signal — it is how "the published artifact" is told apart from "built
    /// here". This is the case a contributor actually hits: the cache holds a
    /// release image that predates the verb they just wrote.
    #[test]
    fn a_downloaded_sidecar_reports_itself_as_published() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let checkout = tempfile::tempdir().unwrap();
        fake_checkout(checkout.path(), "// v1\n");
        let layout = SdkSidecarLayout::under(
            cache.path(),
            FIXTURE_VERSION,
            &GuestArch::host().to_string(),
            GuestLibc::Musl,
        );
        std::fs::create_dir_all(&layout.artifact_dir).unwrap();

        assert_eq!(
            cached_sidecar_provenance(
                cache.path(),
                FIXTURE_VERSION,
                GuestArch::host(),
                GuestLibc::Musl,
                checkout.path(),
            )
            .unwrap(),
            SidecarProvenance::Published,
        );
    }

    /// A sidecar recorded against this tree is current, and an edit to the
    /// cdylib's own sources makes it stale. Both directions, because a
    /// provenance check that can only ever say "stale" carries no information.
    #[test]
    fn a_source_built_sidecar_goes_stale_when_the_cdylib_sources_change() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let checkout = tempfile::tempdir().unwrap();
        fake_checkout(checkout.path(), "// v1\n");

        let fingerprint =
            crate::guest_agent_build::sdk_cdylib_source_fingerprint(checkout.path()).unwrap();
        record_source_fingerprint(
            cache.path(),
            FIXTURE_VERSION,
            GuestArch::host(),
            GuestLibc::Musl,
            &fingerprint,
        )
        .unwrap();

        assert_eq!(
            cached_sidecar_provenance(
                cache.path(),
                FIXTURE_VERSION,
                GuestArch::host(),
                GuestLibc::Musl,
                checkout.path(),
            )
            .unwrap(),
            SidecarProvenance::MatchesSource,
        );

        // The edit that motivated all of this: a new verb in the FFI dispatch.
        // Made in a second checkout, as the next `mvmctl` invocation would
        // see it: one process answers a tree's fingerprint once and keeps it.
        let edited = tempfile::tempdir().unwrap();
        fake_checkout(edited.path(), "// v1\n");
        std::fs::write(
            edited.path().join("crates/mvm-host-services/src/lib.rs"),
            "// v2 — adds host.kv.get\n",
        )
        .unwrap();

        assert_eq!(
            cached_sidecar_provenance(
                cache.path(),
                FIXTURE_VERSION,
                GuestArch::host(),
                GuestLibc::Musl,
                edited.path(),
            )
            .unwrap(),
            SidecarProvenance::StaleSource,
            "an edit to the cdylib's sources must invalidate the cached sidecar"
        );
    }

    #[test]
    fn source_built_install_promotes_artifact_and_fingerprint_together() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let image = sidecar_ext4_bytes(GuestLibc::Musl);
        stage_sidecar_dir(source.path(), FIXTURE_VERSION, &image);

        let artifact = install_source_built_sidecar(
            source.path(),
            cache.path(),
            FIXTURE_VERSION,
            GuestArch::host(),
            GuestLibc::Musl,
            "source-digest",
        )
        .expect("install source-built sidecar");

        assert_eq!(artifact.version, FIXTURE_VERSION);
        let layout = layout_of(cache.path(), GuestLibc::Musl);
        assert_eq!(
            std::fs::read_to_string(layout.artifact_dir.join(LOCAL_SOURCE_FINGERPRINT_FILE))
                .unwrap(),
            "source-digest\n"
        );
    }

    #[test]
    fn source_built_install_refuses_wrong_version_without_replacing_cache() {
        let cache = tempfile::tempdir().unwrap();
        let existing = tempfile::tempdir().unwrap();
        let candidate = tempfile::tempdir().unwrap();
        let old_image = sidecar_ext4_bytes(GuestLibc::Musl);
        let mut new_image = old_image.clone();
        new_image.push(0);
        stage_sidecar_dir(existing.path(), FIXTURE_VERSION, &old_image);
        stage_sidecar_dir(candidate.path(), "wrong-version", &new_image);
        install_sidecar_into_cache(
            existing.path(),
            cache.path(),
            FIXTURE_VERSION,
            &GuestArch::host().to_string(),
            GuestLibc::Musl,
        )
        .expect("seed existing cache");

        let error = install_source_built_sidecar(
            candidate.path(),
            cache.path(),
            FIXTURE_VERSION,
            GuestArch::host(),
            GuestLibc::Musl,
            "source-digest",
        )
        .expect_err("wrong VERSION must be rejected before promotion");

        assert!(
            error.to_string().contains("does not match expected"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(layout_of(cache.path(), GuestLibc::Musl).image).unwrap(),
            old_image
        );
    }

    /// A directory holding the sidecar under other names — a pair cache
    /// entry, whose files carry the producer's `<role>-<arch>-<name>` names —
    /// is refused with the missing canonical path named, not a bare `ENOENT`.
    #[test]
    fn source_built_install_names_the_missing_canonical_file() {
        let cache = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let staged = tempfile::tempdir().unwrap();
        stage_sidecar_dir(
            staged.path(),
            FIXTURE_VERSION,
            &sidecar_ext4_bytes(GuestLibc::Musl),
        );
        for name in SIDECAR_ARCHIVE_MEMBERS {
            std::fs::copy(
                staged.path().join(name),
                source
                    .path()
                    .join(format!("sdk-sidecar-musl-aarch64-{name}")),
            )
            .unwrap();
        }

        let error = install_source_built_sidecar(
            source.path(),
            cache.path(),
            FIXTURE_VERSION,
            GuestArch::host(),
            GuestLibc::Musl,
            "source-digest",
        )
        .expect_err("a directory without the canonical names must be refused");

        let rendered = error.to_string();
        assert!(
            rendered.contains(
                &source
                    .path()
                    .join(SDK_SIDECAR_IMAGE_FILE)
                    .display()
                    .to_string()
            ),
            "the error must name the missing path: {rendered}"
        );
        assert!(
            !layout_of(cache.path(), GuestLibc::Musl)
                .artifact_dir
                .exists()
        );
    }

    #[test]
    fn source_built_install_rejects_an_empty_fingerprint() {
        let cache = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        stage_sidecar_dir(
            source.path(),
            FIXTURE_VERSION,
            &sidecar_ext4_bytes(GuestLibc::Musl),
        );

        let error = install_source_built_sidecar(
            source.path(),
            cache.path(),
            FIXTURE_VERSION,
            GuestArch::host(),
            GuestLibc::Musl,
            "  ",
        )
        .expect_err("empty provenance must not be published");

        assert!(
            error.to_string().contains("fingerprint is empty"),
            "{error}"
        );
        assert!(
            !layout_of(cache.path(), GuestLibc::Musl)
                .artifact_dir
                .exists()
        );
    }

    fn append_file<W: std::io::Write>(tar: &mut tar::Builder<W>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(bytes.len()).unwrap());
        header.set_cksum();
        tar.append_data(&mut header, path, bytes).unwrap();
    }

    /// Append a member whose recorded name is written straight into the header.
    ///
    /// `tar::Builder` refuses to *write* a traversal path, so a hostile fixture
    /// has to bypass it — which is exactly what a malicious publisher would do,
    /// and therefore the only way to exercise the reader's guard for real.
    fn append_raw_named<W: std::io::Write>(tar: &mut tar::Builder<W>, name: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(bytes.len()).unwrap());
        header.set_entry_type(tar::EntryType::Regular);
        {
            let gnu = header.as_gnu_mut().expect("a gnu header");
            gnu.name.fill(0);
            gnu.name[..name.len()].copy_from_slice(name.as_bytes());
        }
        header.set_cksum();
        tar.append(&header, bytes).unwrap();
    }

    fn gzip_tar(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        for (path, bytes) in members {
            append_file(&mut tar, path, bytes);
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    /// The archive a well-formed release publishes: the image, the VERSION
    /// marker, and the derivation's own `sha256sum` manifest over both.
    /// A sound sidecar archive for `libc` labelled `version`, as the image set
    /// publishes it.
    pub(crate) fn well_formed_archive(version: &str, libc: GuestLibc) -> Vec<u8> {
        let image = sidecar_ext4_bytes(libc);
        let version_text = format!("{version}\n").into_bytes();
        let manifest = format!(
            "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
            sha256_hex(&image),
            sha256_hex(&version_text),
        )
        .into_bytes();
        gzip_tar(&[
            (SDK_SIDECAR_IMAGE_FILE, image),
            (SDK_SIDECAR_VERSION_FILE, version_text),
            (CHECKSUM_MANIFEST_FILE, manifest),
        ])
    }

    /// Install `archive` the way a per-version CLI release archive is
    /// installed: written to disk, then extracted, re-checked against its own
    /// manifest and resolved under this fixture's version.
    fn install_for_libc(
        archive: &[u8],
        cache: &Path,
        libc: GuestLibc,
    ) -> Result<SdkSidecarArtifact, String> {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join(archive_name(libc));
        std::fs::write(&path, archive).unwrap();
        install_sdk_sidecar_archive(&path, FIXTURE_VERSION, GuestArch::host(), libc, cache)
            .map_err(|e| format!("{e}"))
    }

    fn install(archive: &[u8], cache: &Path) -> Result<SdkSidecarArtifact, String> {
        install_for_libc(archive, cache, GuestLibc::Glibc)
    }

    fn archive_name(libc: GuestLibc) -> String {
        SdkSidecarArtifactNames::for_target(&GuestArch::host().to_string(), libc).archive
    }

    #[test]
    fn a_published_musl_variant_installs_under_the_musl_key() {
        let cache_dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_dir.path();
        let archive = well_formed_archive(FIXTURE_VERSION, GuestLibc::Musl);

        let artifact = install_for_libc(&archive, cache, GuestLibc::Musl)
            .expect("the published musl sidecar must install");

        assert_eq!(artifact.libc, GuestLibc::Musl);
        assert_eq!(artifact.image, layout_of(cache, GuestLibc::Musl).image);
    }

    /// The cache layout a test staged, for the variant it staged.
    ///
    /// The libc is a parameter rather than a constant because this module
    /// covers two acquisition paths that no longer agree on one: a source
    /// build populates whichever variant it was asked for, while a download
    /// can only ever install the one the release publishes.
    fn layout_of(cache: &Path, libc: GuestLibc) -> SdkSidecarLayout {
        SdkSidecarLayout::under(cache, FIXTURE_VERSION, &GuestArch::host().to_string(), libc)
    }

    /// Nothing a resolver could ever pick up was left behind — the only thing
    /// allowed to remain is an abandoned staging directory.
    fn assert_cache_holds_no_artifact(cache: &Path) {
        let layout = layout_of(cache, GuestLibc::Glibc);
        assert!(
            !layout.artifact_dir.exists(),
            "a refused download must leave no artifact dir at {}",
            layout.artifact_dir.display()
        );
        let members = cache.join(crate::published_image_set::IMAGE_SET_MEMBER_CACHE_DIR);
        assert!(
            !members.exists(),
            "a refused download must install no image-set member under {}",
            members.display()
        );
        assert!(
            SdkSidecarResolver::new(cache.to_path_buf(), FIXTURE_VERSION.to_string())
                .resolve(&GuestArch::host().to_string(), GuestLibc::Glibc)
                .is_err(),
            "a refused download must leave nothing the resolver accepts"
        );
    }

    #[test]
    fn artifact_names_are_arch_and_libc_qualified() {
        let names = SdkSidecarArtifactNames::for_target("aarch64", GuestLibc::Glibc);
        assert_eq!(names.archive, "sdk-sidecar-aarch64-glibc.tar.gz");
        assert_eq!(
            names.archive_checksum,
            "sdk-sidecar-aarch64-glibc.tar.gz.sha256"
        );
        let names = SdkSidecarArtifactNames::for_target("x86_64", GuestLibc::Musl);
        assert_eq!(names.archive, "sdk-sidecar-x86_64-musl.tar.gz");
        assert_eq!(
            names.archive_checksum,
            "sdk-sidecar-x86_64-musl.tar.gz.sha256"
        );
    }

    #[test]
    fn a_well_formed_release_installs_and_resolves() {
        let cache = tempfile::tempdir().unwrap();
        let archive = well_formed_archive(FIXTURE_VERSION, GuestLibc::Glibc);

        let artifact = install(&archive, cache.path()).expect("a sound release installs");

        let layout = layout_of(cache.path(), GuestLibc::Glibc);
        assert_eq!(artifact.image, layout.image);
        assert_eq!(artifact.version, FIXTURE_VERSION);
        assert_eq!(artifact.arch, GuestArch::host().to_string());
        assert_eq!(artifact.image_sha256.len(), 64);
        assert!(layout.image.is_file());
        assert!(layout.version_file.is_file());
        assert!(layout.checksum_manifest_file.is_file());

        // The installed bytes satisfy the same contract the launch path
        // enforces — the transport cannot widen it.
        SdkSidecarResolver::new(cache.path().to_path_buf(), FIXTURE_VERSION.to_string())
            .resolve(&GuestArch::host().to_string(), GuestLibc::Glibc)
            .expect("the installed entry must resolve");
    }

    #[test]
    fn an_archive_entry_that_escapes_the_stage_is_refused() {
        for hostile in ["../escaped", "/etc/passwd", "nested/sdk.ext4"] {
            let cache = tempfile::tempdir().unwrap();
            let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let mut tar = tar::Builder::new(encoder);
            append_file(
                &mut tar,
                SDK_SIDECAR_IMAGE_FILE,
                &sidecar_ext4_bytes(GuestLibc::Glibc),
            );
            append_file(
                &mut tar,
                SDK_SIDECAR_VERSION_FILE,
                format!("{FIXTURE_VERSION}\n").as_bytes(),
            );
            append_file(&mut tar, CHECKSUM_MANIFEST_FILE, b"unused\n");
            append_raw_named(&mut tar, hostile, b"payload");
            let archive = tar.into_inner().unwrap().finish().unwrap();
            let Err(err) = install(&archive, cache.path()) else {
                panic!("{hostile} must be refused");
            };

            assert!(
                err.contains("unsafe or unexpected path"),
                "{hostile} must be refused as an unsafe entry: {err}"
            );
            assert_cache_holds_no_artifact(cache.path());
        }
    }

    #[test]
    fn an_archive_missing_the_image_is_refused() {
        let cache = tempfile::tempdir().unwrap();
        let version_text = format!("{FIXTURE_VERSION}\n").into_bytes();
        let archive = gzip_tar(&[
            (SDK_SIDECAR_VERSION_FILE, version_text.clone()),
            (
                CHECKSUM_MANIFEST_FILE,
                format!(
                    "{}  {SDK_SIDECAR_VERSION_FILE}\n",
                    sha256_hex(&version_text)
                )
                .into_bytes(),
            ),
        ]);
        let err = install(&archive, cache.path()).expect_err("no image, no install");

        assert!(
            err.contains(SDK_SIDECAR_IMAGE_FILE),
            "the refusal must name the missing member: {err}"
        );
        assert_cache_holds_no_artifact(cache.path());
    }

    /// The archive's own manifest is re-checked against the extracted bytes, so
    /// a tarball that is internally inconsistent never reaches the cache — even
    /// though its outer sha256 matches what the signed root declares.
    #[test]
    fn an_inner_manifest_disagreeing_with_the_bytes_is_refused() {
        let cache = tempfile::tempdir().unwrap();
        let version_text = format!("{FIXTURE_VERSION}\n").into_bytes();
        let archive = gzip_tar(&[
            (SDK_SIDECAR_IMAGE_FILE, sidecar_ext4_bytes(GuestLibc::Glibc)),
            (SDK_SIDECAR_VERSION_FILE, version_text.clone()),
            (
                CHECKSUM_MANIFEST_FILE,
                format!(
                    "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
                    "0".repeat(64),
                    sha256_hex(&version_text),
                )
                .into_bytes(),
            ),
        ]);
        let err = install(&archive, cache.path()).expect_err("an inconsistent archive");

        assert!(err.contains("integrity mismatch"), "{err}");
        assert_cache_holds_no_artifact(cache.path());
    }

    /// Staging and promotion are separate steps precisely so a crash between
    /// them is representable: the artifact dir must not exist yet, and the only
    /// residue is a staging directory a later install reaps.
    #[test]
    fn a_crash_between_stage_and_rename_leaves_no_partial_artifact() {
        let cache = tempfile::tempdir().unwrap();
        let layout = layout_of(cache.path(), GuestLibc::Glibc);
        let source = tempfile::tempdir().unwrap();
        let image = sidecar_ext4_bytes(GuestLibc::Glibc);
        let version_text = format!("{FIXTURE_VERSION}\n");
        std::fs::write(source.path().join(SDK_SIDECAR_IMAGE_FILE), &image).unwrap();
        std::fs::write(source.path().join(SDK_SIDECAR_VERSION_FILE), &version_text).unwrap();
        std::fs::write(
            source.path().join(CHECKSUM_MANIFEST_FILE),
            format!(
                "{}  {SDK_SIDECAR_IMAGE_FILE}\n{}  {SDK_SIDECAR_VERSION_FILE}\n",
                sha256_hex(&image),
                sha256_hex(version_text.as_bytes()),
            ),
        )
        .unwrap();

        let parent = layout.artifact_dir.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&parent).unwrap();
        let staging = stage_sidecar_artifact(&parent, &layout.arch, source.path())
            .expect("staging must succeed");

        assert!(
            !layout.artifact_dir.exists(),
            "the artifact dir must not appear until the rename"
        );
        let residue: Vec<String> = std::fs::read_dir(&parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(residue.len(), 1, "unexpected residue: {residue:?}");
        assert!(residue[0].starts_with(&format!("{}.tmp.", layout.arch)));
        assert_eq!(staging.file_name().unwrap().to_string_lossy(), residue[0]);

        // Promotion is what makes it visible, and it is atomic from the
        // resolver's point of view.
        promote_staging(&staging, &layout.artifact_dir).expect("promotion must succeed");
        SdkSidecarResolver::new(cache.path().to_path_buf(), FIXTURE_VERSION.to_string())
            .resolve(&layout.arch, GuestLibc::Glibc)
            .expect("the promoted entry resolves");
    }

    /// A second download over a populated cache replaces it wholesale rather
    /// than merging into it, so a shorter image can never leave stale tail bytes.
    #[test]
    fn a_repeat_download_replaces_the_cached_entry() {
        let cache = tempfile::tempdir().unwrap();
        let archive = well_formed_archive(FIXTURE_VERSION, GuestLibc::Glibc);
        install(&archive, cache.path()).expect("first install");
        let layout = layout_of(cache.path(), GuestLibc::Glibc);
        std::fs::write(layout.artifact_dir.join("stale-residue"), b"x").unwrap();

        install(&archive, cache.path()).expect("second install");

        assert!(
            !layout.artifact_dir.join("stale-residue").exists(),
            "a reinstall must replace the artifact dir, not merge into it"
        );
    }
}
