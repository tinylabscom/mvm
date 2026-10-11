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
//! 2. **Cached.** A previous download, under the mvm cache.
//! 3. **Downloaded** from the release through
//!    [`crate::runtime_overlay::fetch_cli_release_archive`]: the digest its
//!    `.sha256` sidecar records, then the Sigstore bundle under the CLI release
//!    workflow's identity at exactly this version. Only then is the archive
//!    parsed, and only then is it moved into the cache.
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
    verify_guest_bins_archive,
};
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
}

impl std::fmt::Display for ReleaseGuestRuntimeOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Installed => "installed beside mvmctl",
            Self::Cached => "cached",
            Self::Downloaded => "downloaded and verified",
        })
    }
}

/// A release guest runtime that has passed every check.
#[derive(Debug, Clone)]
pub struct ReleaseGuestRuntime {
    pub archive: PathBuf,
    pub manifest: GuestBinsManifest,
    pub origin: ReleaseGuestRuntimeOrigin,
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseGuestRuntimeError {
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

/// The cache directory for `version`'s release guest runtime.
pub fn release_guest_runtime_cache_dir(cache_root: &Path, version: &str) -> PathBuf {
    cache_root
        .join("guest-runtime")
        .join("release")
        .join(version)
}

/// Find or fetch this version's release guest runtime. See the module docs
/// for the order and the checks.
pub fn acquire_release_guest_runtime(
    request: &ReleaseGuestRuntimeRequest<'_>,
) -> Result<ReleaseGuestRuntime, ReleaseGuestRuntimeError> {
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
    let cache_dir = release_guest_runtime_cache_dir(request.cache_root, request.version);
    let cached = cache_dir.join(&name);
    if cached.is_file() {
        return adopt(cached, request.version, ReleaseGuestRuntimeOrigin::Cached);
    }
    download_into_cache(request, &cache_dir, &name)
}

/// Fetch the archive into a staging file beside its cache entry, check it,
/// and only then publish it under its cache name.
fn download_into_cache(
    request: &ReleaseGuestRuntimeRequest<'_>,
    cache_dir: &Path,
    name: &str,
) -> Result<ReleaseGuestRuntime, ReleaseGuestRuntimeError> {
    std::fs::create_dir_all(cache_dir)?;
    let stage = tempfile::Builder::new()
        .prefix(".download-")
        .tempdir_in(cache_dir)?;
    let staged = stage.path().join(name);
    fetch_cli_release_archive(request.release_url, request.version, name, &staged)?;
    let manifest = check_release_archive(&staged, request.version)?;
    let archive = cache_dir.join(name);
    std::fs::rename(&staged, &archive)?;
    Ok(ReleaseGuestRuntime {
        archive,
        manifest,
        origin: ReleaseGuestRuntimeOrigin::Downloaded,
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
    })
}

/// Verify `archive` against its own manifest, then hold the manifest to the
/// release contract: this version, and both architectures' agents.
pub fn check_release_archive(
    archive: &Path,
    version: &str,
) -> Result<GuestBinsManifest, ReleaseGuestRuntimeError> {
    let manifest =
        verify_guest_bins_archive(archive).map_err(|source| ReleaseGuestRuntimeError::Archive {
            path: archive.to_path_buf(),
            source,
        })?;
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
    fn a_downloaded_runtime_is_verified_and_then_cached() {
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
        assert_eq!(first.origin, ReleaseGuestRuntimeOrigin::Downloaded);
        assert_eq!(first.manifest.version, VERSION);
        assert_eq!(std::fs::read(&first.archive).unwrap(), bytes);
        assert!(first.archive.starts_with(cache.path()));

        // The release is gone; the cache answers on its own.
        std::fs::remove_dir_all(release.path()).unwrap();
        let second = acquire_release_guest_runtime(&request(&url, cache.path(), &[])).unwrap();
        assert_eq!(second.origin, ReleaseGuestRuntimeOrigin::Cached);
        assert_eq!(second.archive, first.archive);
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
        let cache = TempDir::new().unwrap();

        let err = acquire_release_guest_runtime(&request(&url, cache.path(), &[]))
            .expect_err("an archive with no signature bundle must be refused");
        assert!(matches!(err, ReleaseGuestRuntimeError::Fetch(_)), "{err:?}");
        let cached = release_guest_runtime_cache_dir(cache.path(), VERSION)
            .join(guest_bins_archive_name(VERSION));
        assert!(!cached.exists(), "a refused archive must not be cached");
    }

    #[test]
    fn a_release_runtime_that_misses_its_digest_is_refused_before_its_signature() {
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
        std::fs::write(dir.join(guest_bins_archive_name(VERSION)), b"not a tarball").unwrap();

        let err = acquire_release_guest_runtime(&request("file:///nowhere", cache.path(), &[]))
            .expect_err("a corrupt cache entry must surface");
        assert!(
            matches!(err, ReleaseGuestRuntimeError::Archive { .. }),
            "{err:?}"
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
