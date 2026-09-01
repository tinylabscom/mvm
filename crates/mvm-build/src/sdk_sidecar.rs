//! Fetch, verify, and install the published SDK-sidecar artifact.
//!
//! Picking a cached sidecar and proving it sound is the resolve half and lives
//! in [`mvm_fs::sdk_sidecar`]. This module owns how one *lands* in the cache on
//! a host that cannot build it: the per-arch release tarball published beside
//! the runtime overlay's, fetched through the same integrity helpers, extracted
//! through the same allow-listed entry validator, and installed through the same
//! stage-then-rename discipline.
//!
//! Every step fails closed. A missing archive checksum, a hash mismatch, an
//! unsafe archive entry, an inner-manifest disagreement, or a post-install
//! resolve failure all return `Err` and leave the cache untouched. There is no
//! degraded install, because a workload admitted to call an SDK-served host
//! service that boots without the cdylib hits an in-guest `dlopen` failure it
//! cannot act on.

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

    /// Underlying io failure while staging or installing.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

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

/// Download the SDK sidecar for `version` + `arch` from the published release,
/// verify it, and install it under `<cache_root>/sdk-sidecar/<version>/<arch>/`.
///
/// The verification ladder, in order, each rung fatal:
///
/// 1. The release's `sha256` sidecar must pre-commit the archive's digest —
///    fetched *before* the payload, so an artifact whose hash cannot be pinned
///    costs no bandwidth and reaches no disk.
/// 2. The downloaded archive must hash to that digest.
/// 3. The archive must verify against the release workflow's cosign-keyless
///    signing identity — the digest alone authenticates the transport, not the
///    publisher. Checked before extraction, so an unauthenticated tar is never
///    parsed.
/// 4. Every archive member must be one of the three canonical files, named by a
///    single unprefixed path component (no traversal, no absolute, no nesting),
///    and all three must be present.
/// 5. The archive's own `checksums-sha256.txt` must agree with the bytes it
///    carried.
/// 6. The *installed* entry must satisfy [`SdkSidecarResolver::resolve`] — the
///    same check the launch path runs — so a transport bug cannot produce a
///    cache entry that only fails later at boot.
///
/// `MVM_SKIP_HASH_VERIFY=1` bypasses rung 2 and `MVM_SKIP_COSIGN_VERIFY=1`
/// bypasses rung 3; both are documented emergency-rotation escapes shared with
/// every other mvm downloader, and neither is ever set in CI. The release base
/// URL is the runtime overlay's (`MVM_OVERLAY_BASE_URL` overrides it for a
/// private mirror or a test fixture) because both artifacts ship in the same
/// release.
pub fn download_sdk_sidecar(
    version: &str,
    arch: GuestArch,
    libc: GuestLibc,
    cache_root: &Path,
) -> Result<SdkSidecarArtifact, SdkSidecarBuildError> {
    if libc == GuestLibc::Unknown {
        return Err(SdkSidecarBuildError::UnknownLibc { arch });
    }

    let arch_dir = arch.to_string();
    let names = SdkSidecarArtifactNames::for_target(&arch_dir, libc);
    let base = crate::runtime_overlay::release_base_url(version);

    let expected = crate::runtime_overlay::fetch_expected_hashes(
        &format!("{base}/{}", names.archive_checksum),
        &[&names.archive],
    )?;

    let tmp = tempfile::tempdir()?;
    let archive_local = tmp.path().join(&names.archive);
    crate::runtime_overlay::curl_download(&format!("{base}/{}", names.archive), &archive_local)?;
    crate::runtime_overlay::verify_file_sha256(
        &archive_local,
        &names.archive,
        expected.get(&names.archive),
    )?;
    // Before extraction: an unauthenticated tar is never parsed.
    crate::release_signature::verify_release_archive_signature(
        &crate::release_signature::ReleaseSignatureRequest {
            base_url: &base,
            asset: &names.archive,
            archive_path: &archive_local,
            version,
            // Unchanged for the same reason as the runtime overlay: the base
            // URL is still CLI-version-derived, so the train must match it.
            train: crate::release_signature::ReleaseTrain::Cli,
        },
    )?;

    let extracted = tmp.path().join("extracted");
    std::fs::create_dir(&extracted)?;
    crate::runtime_overlay::extract_release_archive(
        &archive_local,
        &extracted,
        &SIDECAR_ARCHIVE_MEMBERS,
    )?;
    verify_sidecar_dir_integrity(&extracted)?;

    install_sidecar_into_cache(&extracted, cache_root, version, &arch_dir, libc)?;

    Ok(
        SdkSidecarResolver::new(cache_root.to_path_buf(), version.to_string())
            .resolve(&arch_dir, libc)?,
    )
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
    install_sidecar_with_fingerprint(source, cache_root, version, arch, libc, None)
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
    if fingerprint.trim().is_empty() {
        return Err(SdkSidecarBuildError::InstallInvalid {
            reason: "source fingerprint is empty".to_string(),
        });
    }
    verify_sidecar_dir_integrity(source)?;
    let produced_version = std::fs::read_to_string(source.join(SDK_SIDECAR_VERSION_FILE))?;
    if produced_version.trim() != version {
        return Err(SdkSidecarBuildError::InstallInvalid {
            reason: format!(
                "source-built sidecar VERSION {:?} does not match expected {version:?}",
                produced_version.trim()
            ),
        });
    }
    let arch_dir = arch.to_string();
    install_sidecar_with_fingerprint(
        source,
        cache_root,
        version,
        &arch_dir,
        libc,
        Some(fingerprint.trim()),
    )?;
    Ok(
        SdkSidecarResolver::new(cache_root.to_path_buf(), version.to_string())
            .resolve(&arch_dir, libc)?,
    )
}

fn install_sidecar_with_fingerprint(
    source: &Path,
    cache_root: &Path,
    version: &str,
    arch: &str,
    libc: GuestLibc,
    fingerprint: Option<&str>,
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
    std::fs::create_dir_all(parent)?;
    let staging = stage_sidecar_artifact(parent, arch, source)?;
    if let Some(fingerprint) = fingerprint {
        let marker = staging.join(LOCAL_SOURCE_FINGERPRINT_FILE);
        std::fs::write(&marker, format!("{fingerprint}\n"))?;
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
        std::fs::remove_dir_all(&staging)?;
    }
    // A run killed before its rename orphans a staging dir under another pid
    // that nothing else would ever clean up.
    crate::cache_install::reap_stale_staging(parent, arch);
    std::fs::create_dir(&staging)?;

    for name in SIDECAR_ARCHIVE_MEMBERS {
        let from = source.join(name);
        if !from.is_file() {
            return Err(SdkSidecarBuildError::InstallInvalid {
                reason: format!("verified sidecar source is missing {name}"),
            });
        }
        let to = staging.join(name);
        std::fs::copy(&from, &to)?;
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
        std::fs::remove_dir_all(artifact_dir)?;
    }
    std::fs::rename(staging, artifact_dir)?;
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
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;
    use sha2::{Digest, Sha256};

    const FIXTURE_VERSION: &str = "9.9.9";

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// A minimal sidecar ext4 carrying the one path the resolver proves present,
    /// built with the in-repo pure-Rust writer so the fixture needs no `mkfs`.
    fn sidecar_ext4_bytes() -> Vec<u8> {
        use mvm_fs::ext4::Node;
        let nodes = vec![
            Node::Dir {
                path: "/lib".into(),
                mode: 0o555,
                xattrs: Vec::new(),
            },
            Node::File {
                path: "/lib/libmvm_host_services.so".into(),
                mode: 0o555,
                data: b"\x7fELF-stub".to_vec(),
                xattrs: Vec::new(),
            },
        ];
        mvm_fs::ext4::build_image(nodes).expect("build the sidecar ext4 fixture")
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
        ] {
            std::fs::write(root.join(rel), "[package]\n").unwrap();
        }
        std::fs::write(root.join("crates/mvm-host-services/src/lib.rs"), sdk_src).unwrap();
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
        std::fs::write(
            checkout.path().join("crates/mvm-host-services/src/lib.rs"),
            "// v2 — adds host.kv.get\n",
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
            SidecarProvenance::StaleSource,
            "an edit to the cdylib's sources must invalidate the cached sidecar"
        );
    }

    #[test]
    fn source_built_install_promotes_artifact_and_fingerprint_together() {
        let _env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let image = sidecar_ext4_bytes();
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
        let old_image = sidecar_ext4_bytes();
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

    #[test]
    fn source_built_install_rejects_an_empty_fingerprint() {
        let cache = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        stage_sidecar_dir(source.path(), FIXTURE_VERSION, &sidecar_ext4_bytes());

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
    fn well_formed_archive(version: &str) -> Vec<u8> {
        let image = sidecar_ext4_bytes();
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

    /// What a release directory looks like on disk, so a test can vary exactly
    /// one thing about it.
    struct ReleaseFixture {
        _root: tempfile::TempDir,
        release_dir: PathBuf,
        names: SdkSidecarArtifactNames,
    }

    impl ReleaseFixture {
        /// Stage a release directory carrying `archive`, with the archive's
        /// checksum sidecar computed from `checksum_over` (which is the archive
        /// itself for a sound release, and something else for a drift test).
        fn stage_for_libc(libc: GuestLibc, archive: &[u8], checksum_over: Option<&[u8]>) -> Self {
            let root = tempfile::tempdir().expect("release fixture root");
            let release_dir = root.path().join(format!("v{FIXTURE_VERSION}"));
            std::fs::create_dir_all(&release_dir).expect("create the release dir");
            let names = SdkSidecarArtifactNames::for_target(&GuestArch::host().to_string(), libc);
            std::fs::write(release_dir.join(&names.archive), archive).expect("write the archive");
            if let Some(bytes) = checksum_over {
                std::fs::write(
                    release_dir.join(&names.archive_checksum),
                    format!("{}  {}\n", sha256_hex(bytes), names.archive),
                )
                .expect("write the archive checksum");
            }
            Self {
                _root: root,
                release_dir,
                names,
            }
        }

        fn stage(archive: &[u8], checksum_over: Option<&[u8]>) -> Self {
            Self::stage_for_libc(GuestLibc::Glibc, archive, checksum_over)
        }

        fn sound_for_libc(libc: GuestLibc) -> Self {
            let archive = well_formed_archive(FIXTURE_VERSION);
            let checksum = archive.clone();
            Self::stage_for_libc(libc, &archive, Some(&checksum))
        }

        fn sound() -> Self {
            Self::sound_for_libc(GuestLibc::Glibc)
        }

        fn base_url(&self) -> String {
            format!(
                "file://{}",
                self.release_dir
                    .parent()
                    .expect("the release dir has a parent")
                    .display()
            )
        }
    }

    /// Point the downloader at a staged release directory and give it a cold
    /// cache root. The caller owns the `TestEnv` so its process-wide env lock
    /// spans the whole test, not just the download call.
    ///
    /// The signature rung is skipped here via its documented escape hatch: a
    /// valid Sigstore signature cannot be minted offline, and these tests are
    /// about the digest, extraction, and install rungs. The signature rung has
    /// its own witnesses below and in [`crate::release_signature`].
    fn download_from(
        env: &mut TestEnv,
        fixture: &ReleaseFixture,
        cache: &Path,
    ) -> Result<SdkSidecarArtifact, String> {
        download_from_for_libc(env, fixture, cache, GuestLibc::Glibc)
    }

    fn download_from_for_libc(
        env: &mut TestEnv,
        fixture: &ReleaseFixture,
        cache: &Path,
        libc: GuestLibc,
    ) -> Result<SdkSidecarArtifact, String> {
        env.set("MVM_OVERLAY_BASE_URL", fixture.base_url());
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        download_sdk_sidecar(FIXTURE_VERSION, GuestArch::host(), libc, cache)
            .map_err(|e| format!("{e}"))
    }

    /// Same, but with the signature rung live — so a test can prove the
    /// download refuses an archive the release never signed.
    fn download_with_signature_check(
        env: &mut TestEnv,
        fixture: &ReleaseFixture,
        cache: &Path,
    ) -> Result<SdkSidecarArtifact, String> {
        env.set("MVM_OVERLAY_BASE_URL", fixture.base_url());
        env.remove(crate::release_signature::SKIP_COSIGN_VERIFY_ENV);
        download_sdk_sidecar(FIXTURE_VERSION, GuestArch::host(), GuestLibc::Glibc, cache)
            .map_err(|e| format!("{e}"))
    }

    #[test]
    fn a_published_musl_variant_installs_under_the_musl_key() {
        let mut env = TestEnv::new();
        let cache_dir = tempfile::tempdir().expect("tempdir");
        let cache = cache_dir.path();
        let fixture = ReleaseFixture::sound_for_libc(GuestLibc::Musl);

        let artifact = download_from_for_libc(&mut env, &fixture, cache, GuestLibc::Musl)
            .expect("the published musl sidecar must install");

        assert_eq!(artifact.libc, GuestLibc::Musl);
        assert_eq!(artifact.image, layout_of(cache, GuestLibc::Musl).image);
    }

    #[test]
    fn an_unknown_libc_is_refused_before_transport() {
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().expect("tempdir");
        env.set("MVM_OVERLAY_BASE_URL", "http://127.0.0.1:1/never");

        let error = download_sdk_sidecar(
            FIXTURE_VERSION,
            GuestArch::host(),
            GuestLibc::Unknown,
            cache.path(),
        )
        .expect_err("an unknown libc cannot select a release asset");

        assert!(
            matches!(error, SdkSidecarBuildError::UnknownLibc { .. }),
            "{error}"
        );
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
        assert!(
            SdkSidecarResolver::new(cache.to_path_buf(), FIXTURE_VERSION.to_string())
                .resolve(&GuestArch::host().to_string(), GuestLibc::Glibc)
                .is_err(),
            "a refused download must leave nothing the resolver accepts"
        );
    }

    /// The rung that matters most for an end user: a release that publishes an
    /// archive with no signature beside it is refused, and nothing is cached —
    /// even though the archive's digest matches what the release pinned.
    #[test]
    fn an_unsigned_release_archive_is_refused_and_caches_nothing() {
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let fixture = ReleaseFixture::sound();

        let err = download_with_signature_check(&mut env, &fixture, cache.path())
            .expect_err("an unsigned archive must not install");

        assert!(
            err.contains("signature") || err.contains("bundle"),
            "the refusal must be about the signature: {err}"
        );
        assert!(err.contains(&fixture.names.archive), "{err}");
        assert_cache_holds_no_artifact(cache.path());
    }

    /// Ordering witness: the signature is checked before any tar member is
    /// read. An archive that is both unsigned *and* full of hostile members
    /// must fail on the signature — proving extraction never ran.
    #[test]
    fn the_signature_is_checked_before_the_archive_is_extracted() {
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        append_raw_named(&mut tar, "../escaped", b"payload");
        let archive = tar.into_inner().unwrap().finish().unwrap();
        let fixture = ReleaseFixture::stage(&archive, Some(&archive));

        let err = download_with_signature_check(&mut env, &fixture, cache.path())
            .expect_err("an unsigned archive must not be extracted at all");

        assert!(
            err.contains("signature") || err.contains("bundle"),
            "extraction ran before the signature check: {err}"
        );
        assert!(
            !err.contains("unsafe or unexpected path"),
            "the tar was parsed before its signature was checked: {err}"
        );
        assert_cache_holds_no_artifact(cache.path());
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
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let fixture = ReleaseFixture::sound();

        let artifact =
            download_from(&mut env, &fixture, cache.path()).expect("a sound release installs");

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

    /// The archive checksum is fetched before the payload, so a release missing
    /// it fails naming the checksum URL — proving the tarball was never fetched.
    #[test]
    fn a_missing_archive_checksum_aborts_before_the_tarball_is_fetched() {
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let fixture = ReleaseFixture::stage(&well_formed_archive(FIXTURE_VERSION), None);

        let err =
            download_from(&mut env, &fixture, cache.path()).expect_err("no checksum, no download");

        assert!(
            err.contains(&fixture.names.archive_checksum),
            "the refusal must name the checksum that was absent: {err}"
        );
        assert_cache_holds_no_artifact(cache.path());
    }

    /// A checksums file that exists but does not pre-commit this archive is the
    /// same failure: an artifact whose hash we cannot pin is never fetched.
    #[test]
    fn a_checksum_manifest_without_our_entry_is_refused() {
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let fixture = ReleaseFixture::sound();
        std::fs::write(
            fixture.release_dir.join(&fixture.names.archive_checksum),
            "0000000000000000000000000000000000000000000000000000000000000000  other.tar.gz\n",
        )
        .unwrap();

        let err = download_from(&mut env, &fixture, cache.path())
            .expect_err("an unpinned archive is refused");

        assert!(err.contains("did not list an entry"), "{err}");
        assert_cache_holds_no_artifact(cache.path());
    }

    #[test]
    fn an_archive_hash_mismatch_is_refused_and_caches_nothing() {
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        // The checksum is computed over different bytes than the archive
        // carries — exactly the shape of a substituted payload.
        let fixture = ReleaseFixture::stage(&well_formed_archive(FIXTURE_VERSION), Some(b"other"));

        let err = download_from(&mut env, &fixture, cache.path())
            .expect_err("a drifted archive is refused");

        assert!(err.contains("checksum mismatch"), "{err}");
        assert_cache_holds_no_artifact(cache.path());
    }

    #[test]
    fn an_archive_entry_that_escapes_the_stage_is_refused() {
        let mut env = TestEnv::new();
        for hostile in ["../escaped", "/etc/passwd", "nested/sdk.ext4"] {
            let cache = tempfile::tempdir().unwrap();
            let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let mut tar = tar::Builder::new(encoder);
            append_file(&mut tar, SDK_SIDECAR_IMAGE_FILE, &sidecar_ext4_bytes());
            append_file(
                &mut tar,
                SDK_SIDECAR_VERSION_FILE,
                format!("{FIXTURE_VERSION}\n").as_bytes(),
            );
            append_file(&mut tar, CHECKSUM_MANIFEST_FILE, b"unused\n");
            append_raw_named(&mut tar, hostile, b"payload");
            let archive = tar.into_inner().unwrap().finish().unwrap();
            let fixture = ReleaseFixture::stage(&archive, Some(&archive));

            let Err(err) = download_from(&mut env, &fixture, cache.path()) else {
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
        let mut env = TestEnv::new();
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
        let fixture = ReleaseFixture::stage(&archive, Some(&archive));

        let err =
            download_from(&mut env, &fixture, cache.path()).expect_err("no image, no install");

        assert!(
            err.contains(SDK_SIDECAR_IMAGE_FILE),
            "the refusal must name the missing member: {err}"
        );
        assert_cache_holds_no_artifact(cache.path());
    }

    /// The archive's own manifest is re-checked against the extracted bytes, so
    /// a tarball that is internally inconsistent never reaches the cache — even
    /// though its outer sha256 matches what the release pinned.
    #[test]
    fn an_inner_manifest_disagreeing_with_the_bytes_is_refused() {
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let version_text = format!("{FIXTURE_VERSION}\n").into_bytes();
        let archive = gzip_tar(&[
            (SDK_SIDECAR_IMAGE_FILE, sidecar_ext4_bytes()),
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
        let fixture = ReleaseFixture::stage(&archive, Some(&archive));

        let err =
            download_from(&mut env, &fixture, cache.path()).expect_err("an inconsistent archive");

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
        let image = sidecar_ext4_bytes();
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
        let mut env = TestEnv::new();
        let cache = tempfile::tempdir().unwrap();
        let fixture = ReleaseFixture::sound();
        download_from(&mut env, &fixture, cache.path()).expect("first install");
        let layout = layout_of(cache.path(), GuestLibc::Glibc);
        std::fs::write(layout.artifact_dir.join("stale-residue"), b"x").unwrap();

        download_from(&mut env, &fixture, cache.path()).expect("second install");

        assert!(
            !layout.artifact_dir.join("stale-residue").exists(),
            "a reinstall must replace the artifact dir, not merge into it"
        );
    }
}
