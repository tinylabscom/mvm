//! The guest runtime a CLI release ships: the `mvm-guest-bins` archive,
//! published beside the `mvmctl` tarballs as a signed asset of the same
//! release and version-locked to it.
//!
//! A downloaded `mvmctl` gets its own version's archive from one of three
//! places, in order:
//!
//! 1. **Installed beside it.** `install.sh` stages the archive in the release
//!    directory under `guest-runtime/`, and the deb and rpm packages put it
//!    under `/usr/lib/mvmctl/guest-runtime/`. Both installers authenticated
//!    it against the release signature before placing it there, the same way
//!    they authenticated the `mvmctl` next to it.
//! 2. **Cached** in [`release_guest_runtime_cache_dir`], the directory a
//!    launch authenticates the archive from. The entry is checked with the
//!    launch's own verifier before it is used.
//! 3. **Downloaded** from the release: every file in
//!    [`release_guest_runtime_files`] into a staging directory, checked there
//!    with that same verifier (the archive's digest against the `.sha256`
//!    file, the `.sha256` file's signature, and the archive's signature, under
//!    the CLI release workflow's identity at exactly this version), and only
//!    then published as the cache entry. The files kept are the files checked.
//!
//! `MVM_SKIP_COSIGN_VERIFY` lets a download proceed with the archive's
//! signature unchecked (and its digest too when `MVM_SKIP_HASH_VERIFY` is also
//! set). Such a download is returned from a private temporary directory and is
//! never written to [`release_guest_runtime_cache_dir`], so that directory
//! holds only evidence that verified. For the guest runtime the hatch accepts
//! an unverified download, not an unverified install: nothing is installed
//! from such a result. Installing takes an [`AuthenticatedReleaseArchive`], and
//! [`ReleaseGuestRuntime::authenticated_archive`] refuses to make one from an
//! [`ReleaseGuestRuntimeOrigin::Unverified`] result, so the object store, the
//! launch pieces, the OCI shims and the adoption record stay as they were.
//! Acquisition itself still succeeds and returns the archive, for a caller
//! that does not install it.
//!
//! Whichever place answers, the archive must verify against its own manifest
//! and that manifest must name this version and carry both architectures. A
//! file that is present and fails is an error, never a reason to fetch a
//! replacement: a corrupt installed or cached runtime is evidence, and quietly
//! downloading over it would hide that.

use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;

use super::{
    GuestBinsError, GuestBinsManifest, GuestBinsMember, guest_bins_archive_name,
    read_release_manifest, verify_guest_bins_archive,
};
use crate::guest_runtime::{self, GuestRuntimeError, ReleaseArchiveCheck};
use crate::runtime_overlay::{RuntimeOverlayError, fetch_cli_release_archive};

/// The architectures every released guest runtime carries.
pub const RELEASE_GUEST_RUNTIME_ARCHES: [GuestArch; 2] = [GuestArch::Aarch64, GuestArch::X86_64];

/// Where an installer puts the archive, relative to the directory holding the
/// real `mvmctl` executable: `install.sh`'s release directory.
pub const INSTALLED_GUEST_RUNTIME_DIR: &str = "guest-runtime";

/// Where a distribution package puts the archive, relative to the directory
/// holding `mvmctl` (`/usr/bin` → `/usr/lib/mvmctl/guest-runtime`).
pub const PACKAGED_GUEST_RUNTIME_DIR: &str = "../lib/mvmctl/guest-runtime";

/// What to acquire, and where to look for it.
#[derive(Debug, Clone)]
pub struct ReleaseGuestRuntimeRequest<'a> {
    /// The per-version release directory, e.g.
    /// `https://github.com/<repo>/releases/download/v1.2.3`.
    pub release_url: &'a str,
    /// The CLI version, without a leading `v`.
    pub version: &'a str,
    /// The mvm cache root.
    pub cache_root: &'a Path,
    /// Directories an installer may have placed the archive in, searched in
    /// order before the cache.
    pub installed_dirs: &'a [PathBuf],
}

/// Which of the three places the archive came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseGuestRuntimeOrigin {
    Installed,
    Cached,
    Downloaded,
    /// Downloaded with `MVM_SKIP_COSIGN_VERIFY` set: its signature was not
    /// checked, and it was not written to the release cache a launch
    /// authenticates from.
    Unverified,
}

impl std::fmt::Display for ReleaseGuestRuntimeOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Installed => "installed beside mvmctl",
            Self::Cached => "cached",
            Self::Downloaded => "downloaded and verified",
            Self::Unverified => {
                "downloaded with its signature unchecked; not kept in the release cache"
            }
        })
    }
}

/// A release guest runtime archive that may be installed: one installed
/// beside `mvmctl` by an installer that authenticated it, or cached or
/// downloaded and verified against its release signature. Outside this crate
/// the only way to make one is [`ReleaseGuestRuntime::authenticated_archive`],
/// which refuses an [`ReleaseGuestRuntimeOrigin::Unverified`] result.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedReleaseArchive<'a> {
    path: &'a Path,
}

impl<'a> AuthenticatedReleaseArchive<'a> {
    /// For a caller in this crate that authenticated `path` itself.
    pub(crate) fn assume_authenticated(path: &'a Path) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &'a Path {
        self.path
    }
}

/// A release guest runtime that has passed every check.
#[derive(Debug, Clone)]
pub struct ReleaseGuestRuntime {
    pub archive: PathBuf,
    pub manifest: GuestBinsManifest,
    pub origin: ReleaseGuestRuntimeOrigin,
    /// The private directory holding a [`ReleaseGuestRuntimeOrigin::Unverified`]
    /// archive, removed when the last clone is dropped. Keep the whole value,
    /// not just [`Self::archive`], for as long as the archive is read.
    pub unpublished: Option<std::sync::Arc<tempfile::TempDir>>,
}

impl ReleaseGuestRuntime {
    /// The archive, for installing: copying into the object store, assembling
    /// the launch pieces and OCI shims, and recording the adoption. Refused
    /// when the signature check was skipped, so the hatch never turns an
    /// unverified download into an install.
    pub fn authenticated_archive(
        &self,
    ) -> Result<AuthenticatedReleaseArchive<'_>, ReleaseGuestRuntimeError> {
        match self.origin {
            ReleaseGuestRuntimeOrigin::Installed
            | ReleaseGuestRuntimeOrigin::Cached
            | ReleaseGuestRuntimeOrigin::Downloaded => Ok(
                AuthenticatedReleaseArchive::assume_authenticated(&self.archive),
            ),
            ReleaseGuestRuntimeOrigin::Unverified => Err(ReleaseGuestRuntimeError::Unverified {
                name: self
                    .archive
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseGuestRuntimeError {
    #[error(
        "{name} was downloaded with {env} set, so its signature was not checked and it was kept \
         out of the install: no launch pieces, OCI shims or adoption record were written. Unset \
         {env} and run `mvmctl bootstrap` again",
        env = crate::release_signature::SKIP_COSIGN_VERIFY_ENV
    )]
    Unverified { name: String },
    #[error("fetch the guest runtime from the release: {0}")]
    Fetch(#[source] Box<RuntimeOverlayError>),
    #[error("{} is not a valid guest runtime: {source}", path.display())]
    Archive {
        path: PathBuf,
        #[source]
        source: GuestBinsError,
    },
    #[error(
        "{} carries guest runtime {actual}, but this mvmctl is {expected}; \
         the CLI and its guest runtime ship together",
        path.display()
    )]
    Version {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("{} has no {member}; a released guest runtime carries both architectures", path.display())]
    Incomplete { path: PathBuf, member: String },
    #[error("guest runtime cache: {0}")]
    Io(#[from] std::io::Error),
    #[error("release guest runtime: {0}")]
    Release(#[from] GuestRuntimeError),
}

impl From<RuntimeOverlayError> for ReleaseGuestRuntimeError {
    fn from(error: RuntimeOverlayError) -> Self {
        Self::Fetch(Box::new(error))
    }
}

/// The directories an installer may have put the archive in for the
/// executable at `exe`, resolved through any links: `install.sh` links
/// `mvmctl` into the PATH directory, and the archive sits beside the real file.
pub fn installed_guest_runtime_dirs(exe: &Path) -> Vec<PathBuf> {
    let exe = exe.canonicalize().unwrap_or_else(|_| exe.to_path_buf());
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    vec![
        dir.join(INSTALLED_GUEST_RUNTIME_DIR),
        dir.join(PACKAGED_GUEST_RUNTIME_DIR),
    ]
}

/// The one cache directory for `version`'s release guest runtime: acquisition
/// publishes [`release_guest_runtime_files`] here once they verify, and a
/// launch authenticates the archive from them again.
pub fn release_guest_runtime_cache_dir(cache_root: &Path, version: &str) -> PathBuf {
    cache_root
        .join("guest-runtime")
        .join("releases")
        .join(version)
}

/// The files a release guest runtime is kept as, archive first: the archive,
/// its `.sha256` sidecar, and the signature bundles of both. A launch needs
/// the first three; it checks the `.sha256` file's signature when that bundle
/// is present, and acquisition always keeps it.
pub fn release_guest_runtime_files(version: &str) -> [String; 4] {
    let archive = guest_bins_archive_name(version);
    [
        archive.clone(),
        format!("{archive}.sha256"),
        format!("{archive}.bundle"),
        format!("{archive}.sha256.bundle"),
    ]
}

/// Find or fetch this version's release guest runtime. See the module docs
/// for the order and the checks.
pub fn acquire_release_guest_runtime(
    request: &ReleaseGuestRuntimeRequest<'_>,
) -> Result<ReleaseGuestRuntime, ReleaseGuestRuntimeError> {
    let arch = GuestArch::host();
    acquire_with(
        request,
        arch,
        &guest_runtime::release_identity_check(request.version, arch),
    )
}

/// [`acquire_release_guest_runtime`] with the verifier as a parameter. Crate
/// private, so no other crate can supply a check of its own.
pub(crate) fn acquire_with(
    request: &ReleaseGuestRuntimeRequest<'_>,
    arch: GuestArch,
    verify: &ReleaseArchiveCheck<'_>,
) -> Result<ReleaseGuestRuntime, ReleaseGuestRuntimeError> {
    guest_runtime::check_release_version(request.version)?;
    let name = guest_bins_archive_name(request.version);
    for dir in request.installed_dirs {
        let candidate = dir.join(&name);
        if candidate.is_file() {
            return adopt(
                candidate,
                request.version,
                ReleaseGuestRuntimeOrigin::Installed,
            );
        }
    }
    let entry = release_guest_runtime_cache_dir(request.cache_root, request.version);
    let cached = match std::fs::symlink_metadata(&entry) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if !cached && std::env::var_os(crate::release_signature::SKIP_COSIGN_VERIFY_ENV).is_some() {
        return download_unpublished(request, &name);
    }
    let runtime = guest_runtime::resolve_release_guest_runtime_with(
        request.cache_root,
        request.version,
        arch,
        &[],
        request.release_url,
        true,
        verify,
    )?;
    let proof = runtime
        .release_proof
        .ok_or_else(|| std::io::Error::other("verified release runtime carries no proof"))?;
    Ok(ReleaseGuestRuntime {
        archive: proof.archive,
        manifest: runtime.manifest,
        origin: if cached {
            ReleaseGuestRuntimeOrigin::Cached
        } else {
            ReleaseGuestRuntimeOrigin::Downloaded
        },
        unpublished: None,
    })
}

/// With the signature check waived, fetch the archive (held to its digest
/// unless that check is waived too) into a private directory that lives as
/// long as the result, never into the release cache a launch reads.
fn download_unpublished(
    request: &ReleaseGuestRuntimeRequest<'_>,
    name: &str,
) -> Result<ReleaseGuestRuntime, ReleaseGuestRuntimeError> {
    let stage = tempfile::Builder::new()
        .prefix("mvm-unverified-guest-runtime-")
        .tempdir()?;
    let archive = stage.path().join(name);
    fetch_cli_release_archive(request.release_url, request.version, name, &archive)?;
    let manifest = check_release_archive(&archive, request.version)?;
    Ok(ReleaseGuestRuntime {
        archive,
        manifest,
        origin: ReleaseGuestRuntimeOrigin::Unverified,
        unpublished: Some(std::sync::Arc::new(stage)),
    })
}

fn adopt(
    archive: PathBuf,
    version: &str,
    origin: ReleaseGuestRuntimeOrigin,
) -> Result<ReleaseGuestRuntime, ReleaseGuestRuntimeError> {
    let manifest = check_release_archive(&archive, version)?;
    Ok(ReleaseGuestRuntime {
        archive,
        manifest,
        origin,
        unpublished: None,
    })
}

/// Verify `archive` against its own manifest, then hold the manifest to the
/// release contract: this version, and both architectures' agents.
pub fn check_release_archive(
    archive: &Path,
    version: &str,
) -> Result<GuestBinsManifest, ReleaseGuestRuntimeError> {
    let archive_error = |source| ReleaseGuestRuntimeError::Archive {
        path: archive.to_path_buf(),
        source,
    };
    // The manifest must be the first entry: a launch reads it from there.
    std::fs::File::open(archive)
        .map_err(GuestBinsError::from)
        .and_then(read_release_manifest)
        .map_err(archive_error)?;
    let manifest = verify_guest_bins_archive(archive).map_err(archive_error)?;
    check_release_manifest(&manifest, archive, version)?;
    Ok(manifest)
}

fn check_release_manifest(
    manifest: &GuestBinsManifest,
    archive: &Path,
    version: &str,
) -> Result<(), ReleaseGuestRuntimeError> {
    if manifest.version != version {
        return Err(ReleaseGuestRuntimeError::Version {
            path: archive.to_path_buf(),
            expected: version.to_string(),
            actual: manifest.version.clone(),
        });
    }
    for member in required_release_members() {
        if !manifest.files.contains_key(&member) {
            return Err(ReleaseGuestRuntimeError::Incomplete {
                path: archive.to_path_buf(),
                member,
            });
        }
    }
    Ok(())
}

/// The members whose absence means the archive is not a whole release guest
/// runtime: each architecture's guest agent and initramfs agent.
fn required_release_members() -> Vec<String> {
    RELEASE_GUEST_RUNTIME_ARCHES
        .into_iter()
        .flat_map(|arch| {
            [
                GuestBinsMember::Executable {
                    arch,
                    name: "mvm-guest-agent".to_string(),
                }
                .path(),
                GuestBinsMember::InitramfsAgent { arch }.path(),
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guest_agent_build::fake_static_elf;
    use crate::guest_bins::{GuestBinsArtifact, GuestBinsFingerprints};
    use crate::image_source::RepoIdentity;
    use mvm_core::image_set::{GitCommit, WorktreeState};
    use mvm_core::util::test_env::TestEnv;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    const VERSION: &str = "9.9.9";

    fn artifact(version: &str, arches: &[GuestArch]) -> GuestBinsArtifact {
        let mut artifact = GuestBinsArtifact::new(
            version,
            GuestBinsFingerprints {
                guest_source: "g".repeat(64),
                sdk_cdylib: "c".repeat(64),
            },
            RepoIdentity {
                commit: GitCommit::new("a".repeat(40)).unwrap(),
                worktree: WorktreeState::Clean,
            },
        );
        let bins = TempDir::new().unwrap();
        for &arch in arches {
            let path = bins.path().join(format!("{arch}"));
            std::fs::write(&path, fake_static_elf(arch, b"agent")).unwrap();
            artifact
                .add(
                    &GuestBinsMember::executable(arch, "mvm-guest-agent").unwrap(),
                    &path,
                )
                .unwrap();
            artifact
                .add(&GuestBinsMember::InitramfsAgent { arch }, &path)
                .unwrap();
        }
        artifact
    }

    /// Write `version`'s archive into `dir` and return its path.
    fn write_archive(dir: &Path, version: &str, arches: &[GuestArch]) -> PathBuf {
        artifact(version, arches).write(dir).unwrap().archive
    }

    /// A release directory the way `release.yml` publishes one: the archive
    /// and its `.sha256` sidecar.
    fn stage_release(root: &Path, archive_bytes: &[u8]) -> String {
        let name = guest_bins_archive_name(VERSION);
        std::fs::write(root.join(&name), archive_bytes).unwrap();
        std::fs::write(
            root.join(format!("{name}.sha256")),
            format!("{}  {name}\n", hex::encode(Sha256::digest(archive_bytes))),
        )
        .unwrap();
        format!("file://{}", root.display())
    }

    fn request<'a>(
        release_url: &'a str,
        cache_root: &'a Path,
        installed_dirs: &'a [PathBuf],
    ) -> ReleaseGuestRuntimeRequest<'a> {
        ReleaseGuestRuntimeRequest {
            release_url,
            version: VERSION,
            cache_root,
            installed_dirs,
        }
    }

    #[test]
    fn a_download_with_the_signature_hatch_proceeds_but_is_never_cached() {
        let mut env = TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        let build = TempDir::new().unwrap();
        let bytes = std::fs::read(write_archive(
            build.path(),
            VERSION,
            &RELEASE_GUEST_RUNTIME_ARCHES,
        ))
        .unwrap();
        let release = TempDir::new().unwrap();
        let url = stage_release(release.path(), &bytes);
        let cache = TempDir::new().unwrap();

        let first = acquire_release_guest_runtime(&request(&url, cache.path(), &[])).unwrap();
        assert_eq!(first.origin, ReleaseGuestRuntimeOrigin::Unverified);
        assert_eq!(first.manifest.version, VERSION);
        assert_eq!(std::fs::read(&first.archive).unwrap(), bytes);
        assert!(
            !release_guest_runtime_cache_dir(cache.path(), VERSION).exists(),
            "unverified evidence must never reach the cache a launch reads"
        );
        assert!(!first.archive.starts_with(cache.path()));

        // Acquisition returns the archive; installing it is refused.
        assert!(matches!(
            first.authenticated_archive(),
            Err(ReleaseGuestRuntimeError::Unverified { name }) if name == guest_bins_archive_name(VERSION)
        ));

        // Nothing was cached, so the next acquisition downloads again, and
        // the unverified copy goes when its last holder does.
        let second = acquire_release_guest_runtime(&request(&url, cache.path(), &[])).unwrap();
        assert_eq!(second.origin, ReleaseGuestRuntimeOrigin::Unverified);
        let archive = first.archive.clone();
        drop(first);
        assert!(!archive.exists());
    }

    #[test]
    fn only_an_unverified_download_is_refused_an_authenticated_archive() {
        let runtime = |origin| ReleaseGuestRuntime {
            archive: PathBuf::from("/r").join(guest_bins_archive_name(VERSION)),
            manifest: artifact(VERSION, &RELEASE_GUEST_RUNTIME_ARCHES).manifest(),
            origin,
            unpublished: None,
        };
        for origin in [
            ReleaseGuestRuntimeOrigin::Installed,
            ReleaseGuestRuntimeOrigin::Cached,
            ReleaseGuestRuntimeOrigin::Downloaded,
        ] {
            let release = runtime(origin);
            assert_eq!(
                release.authenticated_archive().unwrap().path(),
                release.archive,
                "{origin}"
            );
        }
        let error = runtime(ReleaseGuestRuntimeOrigin::Unverified)
            .authenticated_archive()
            .expect_err("a download whose signature was not checked is never installed");
        assert!(matches!(
            &error,
            ReleaseGuestRuntimeError::Unverified { name } if *name == guest_bins_archive_name(VERSION)
        ));
        // The refusal says why and what to do.
        let rendered = error.to_string();
        assert!(
            rendered.contains(crate::release_signature::SKIP_COSIGN_VERIFY_ENV)
                && rendered.contains("mvmctl bootstrap"),
            "{rendered}"
        );
    }

    /// With the digest hatch set as well, the download is not held to its
    /// digest either, and installing it is refused just the same.
    #[test]
    fn both_hatches_still_return_the_bytes_and_still_refuse_the_install() {
        let mut env = TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        env.set(crate::runtime_overlay::SKIP_HASH_VERIFY_ENV, "1");
        let build = TempDir::new().unwrap();
        let bytes = std::fs::read(write_archive(
            build.path(),
            VERSION,
            &RELEASE_GUEST_RUNTIME_ARCHES,
        ))
        .unwrap();
        let release = TempDir::new().unwrap();
        let url = stage_release(release.path(), b"a digest these bytes do not have");
        std::fs::write(
            release.path().join(guest_bins_archive_name(VERSION)),
            &bytes,
        )
        .unwrap();
        let cache = TempDir::new().unwrap();

        let runtime = acquire_release_guest_runtime(&request(&url, cache.path(), &[])).unwrap();
        assert_eq!(runtime.origin, ReleaseGuestRuntimeOrigin::Unverified);
        assert_eq!(std::fs::read(&runtime.archive).unwrap(), bytes);
        assert!(matches!(
            runtime.authenticated_archive(),
            Err(ReleaseGuestRuntimeError::Unverified { .. })
        ));
        assert!(std::fs::read_dir(cache.path()).unwrap().next().is_none());
    }

    #[test]
    fn an_unsigned_release_runtime_is_refused_and_nothing_is_cached() {
        let mut env = TestEnv::new();
        env.remove(crate::release_signature::SKIP_COSIGN_VERIFY_ENV);
        let build = TempDir::new().unwrap();
        let bytes = std::fs::read(write_archive(
            build.path(),
            VERSION,
            &RELEASE_GUEST_RUNTIME_ARCHES,
        ))
        .unwrap();
        let release = TempDir::new().unwrap();
        let url = stage_release(release.path(), &bytes);
        // Both bundles are present, so nothing fails to download: only the
        // signature check can refuse this release.
        let name = guest_bins_archive_name(VERSION);
        std::fs::write(
            release.path().join(format!("{name}.bundle")),
            b"not a bundle",
        )
        .unwrap();
        std::fs::write(
            release.path().join(format!("{name}.sha256.bundle")),
            b"not a bundle",
        )
        .unwrap();
        let cache = TempDir::new().unwrap();

        let err = acquire_release_guest_runtime(&request(&url, cache.path(), &[]))
            .expect_err("an archive whose signatures do not verify must be refused");
        assert!(
            matches!(
                &err,
                ReleaseGuestRuntimeError::Release(GuestRuntimeError::Release(
                    RuntimeOverlayError::SignatureInvalid { .. }
                ))
            ),
            "{err:?}"
        );
        let entry = release_guest_runtime_cache_dir(cache.path(), VERSION);
        assert!(!entry.exists(), "a refused archive must not be cached");
        assert!(
            std::fs::read_dir(entry.parent().unwrap())
                .unwrap()
                .all(|e| !e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".download-")),
            "the staging directory is removed"
        );
    }

    #[test]
    fn a_hatched_download_is_still_held_to_its_digest() {
        let mut env = TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        env.remove(crate::runtime_overlay::SKIP_HASH_VERIFY_ENV);
        let release = TempDir::new().unwrap();
        let url = stage_release(release.path(), b"the-real-bytes");
        std::fs::write(
            release.path().join(guest_bins_archive_name(VERSION)),
            b"tampered!",
        )
        .unwrap();
        let cache = TempDir::new().unwrap();

        let err = acquire_release_guest_runtime(&request(&url, cache.path(), &[]))
            .expect_err("a digest mismatch must be refused");
        assert!(
            matches!(
                &err,
                ReleaseGuestRuntimeError::Fetch(inner)
                    if matches!(**inner, RuntimeOverlayError::ChecksumMismatch { .. })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn an_installed_runtime_wins_without_any_network() {
        let installed = TempDir::new().unwrap();
        write_archive(installed.path(), VERSION, &RELEASE_GUEST_RUNTIME_ARCHES);
        let cache = TempDir::new().unwrap();
        let dirs = [
            installed.path().join("absent"),
            installed.path().to_path_buf(),
        ];

        let runtime =
            acquire_release_guest_runtime(&request("file:///nowhere", cache.path(), &dirs))
                .unwrap();
        assert_eq!(runtime.origin, ReleaseGuestRuntimeOrigin::Installed);
        assert!(runtime.archive.starts_with(installed.path()));
    }

    #[test]
    fn an_installed_runtime_for_another_version_is_refused_not_replaced() {
        let installed = TempDir::new().unwrap();
        let other = write_archive(installed.path(), "9.9.8", &RELEASE_GUEST_RUNTIME_ARCHES);
        std::fs::rename(
            &other,
            installed.path().join(guest_bins_archive_name(VERSION)),
        )
        .unwrap();
        let cache = TempDir::new().unwrap();
        let dirs = [installed.path().to_path_buf()];

        let err = acquire_release_guest_runtime(&request("file:///nowhere", cache.path(), &dirs))
            .expect_err("a mismatched installed runtime must not be adopted");
        assert!(
            matches!(&err, ReleaseGuestRuntimeError::Version { actual, .. } if actual == "9.9.8"),
            "{err:?}"
        );
    }

    #[test]
    fn a_tampered_cached_runtime_is_an_error_not_a_refetch() {
        let cache = TempDir::new().unwrap();
        let dir = release_guest_runtime_cache_dir(cache.path(), VERSION);
        std::fs::create_dir_all(&dir).unwrap();
        // The entry was cached with its evidence, and then the archive changed.
        let name = guest_bins_archive_name(VERSION);
        std::fs::write(dir.join(&name), b"not a tarball").unwrap();
        std::fs::write(
            dir.join(format!("{name}.sha256")),
            format!(
                "{}  {name}\n",
                hex::encode(Sha256::digest(b"the cached bytes"))
            ),
        )
        .unwrap();
        std::fs::write(dir.join(format!("{name}.bundle")), b"bundle").unwrap();

        let err = acquire_release_guest_runtime(&request("file:///nowhere", cache.path(), &[]))
            .expect_err("a corrupt cache entry must surface");
        assert!(
            matches!(
                &err,
                ReleaseGuestRuntimeError::Release(GuestRuntimeError::CachedReleaseEvidence {
                    dir: entry,
                    source,
                    ..
                }) if *entry == dir && matches!(
                    &**source,
                    GuestRuntimeError::Cache(reason) if reason.contains("checksum missing or mismatched")
                )
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("remove that directory"), "{err}");
        assert_eq!(
            std::fs::read(dir.join(guest_bins_archive_name(VERSION))).unwrap(),
            b"not a tarball",
            "the corrupt entry is left as evidence"
        );
    }

    #[test]
    fn a_single_architecture_archive_is_not_a_release_runtime() {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(dir.path(), VERSION, &[GuestArch::Aarch64]);

        let err = check_release_archive(&archive, VERSION)
            .expect_err("a release runtime carries both architectures");
        assert!(
            matches!(&err, ReleaseGuestRuntimeError::Incomplete { member, .. }
                if member.starts_with("x86_64/")),
            "{err:?}"
        );
    }

    /// Rewrite `archive` with its entries (in archive order) edited by `edit`.
    fn rewrite_entries(archive: &Path, edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>)) {
        let mut members = Vec::new();
        let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(
            std::fs::File::open(archive).unwrap(),
        ));
        for entry in tar.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut bytes).unwrap();
            members.push((path, bytes));
        }
        edit(&mut members);
        let mut out = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (path, bytes) in &members {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            out.append(&header, &bytes[..]).unwrap();
        }
        std::fs::write(archive, out.into_inner().unwrap().finish().unwrap()).unwrap();
    }

    /// An archive that is consistent in every way except that the manifest
    /// is the last entry rather than the first.
    #[test]
    fn an_archive_whose_manifest_is_not_first_is_refused() {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(dir.path(), VERSION, &RELEASE_GUEST_RUNTIME_ARCHES);
        check_release_archive(&archive, VERSION).unwrap();
        rewrite_entries(&archive, |members| members.rotate_left(1));

        // The full walk still passes: only the order changed.
        verify_guest_bins_archive(&archive).unwrap();
        assert!(matches!(
            check_release_archive(&archive, VERSION),
            Err(ReleaseGuestRuntimeError::Archive {
                source: GuestBinsError::ManifestNotFirst(_),
                ..
            })
        ));
    }

    /// The first-entry reader accepts a manifest-first archive whatever
    /// follows, so a second `manifest.json` later on is refused only by the
    /// full walk. A launch that used the reader alone would not see it.
    #[test]
    fn a_duplicate_later_manifest_is_accepted_by_the_reader_and_refused_by_the_walk() {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(dir.path(), VERSION, &RELEASE_GUEST_RUNTIME_ARCHES);
        rewrite_entries(&archive, |members| {
            let manifest = members[0].clone();
            members.push(manifest);
        });
        read_release_manifest(std::fs::File::open(&archive).unwrap()).unwrap();
        assert!(matches!(
            check_release_archive(&archive, VERSION),
            Err(ReleaseGuestRuntimeError::Archive {
                source: GuestBinsError::DuplicateMember(_),
                ..
            })
        ));
    }

    #[test]
    fn installers_place_the_runtime_beside_the_real_executable() {
        let root = TempDir::new().unwrap();
        let release = root.path().join("lib/mvm/1-v9.9.9");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(release.join("mvmctl"), b"").unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(release.join("mvmctl"), bin.join("mvmctl")).unwrap();
        #[cfg(not(unix))]
        std::fs::write(bin.join("mvmctl"), b"").unwrap();

        let dirs = installed_guest_runtime_dirs(&bin.join("mvmctl"));
        #[cfg(unix)]
        {
            let release = release.canonicalize().unwrap();
            assert_eq!(
                dirs,
                [
                    release.join("guest-runtime"),
                    release.join("../lib/mvmctl/guest-runtime"),
                ]
            );
        }
        #[cfg(not(unix))]
        assert_eq!(dirs.len(), 2);
    }
}
