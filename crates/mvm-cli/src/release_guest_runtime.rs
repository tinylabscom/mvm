//! The guest runtime a downloaded `mvmctl` ships with.
//!
//! Each CLI release publishes the `mvm-guest-bins` archive beside its
//! tarballs, signed under the same release identity. Two commands acquire it:
//! `mvmctl bootstrap` on a release binary, for the binary's own version, and
//! `mvmctl env update`, for the version it is about to install, before the
//! running binary is touched. The acquisition itself — installed copy, cache,
//! or download held to its digest and then its signature — is
//! [`mvm_build::guest_bins::release`]. Bootstrap then assembles the runtime
//! overlay, the initramfs, both SDK sidecars and the OCI guest runtime from
//! the archive it acquired
//! ([`mvm_build::runtime_pieces::assemble_release_runtime_pieces`]).
//!
//! A source build assembles its guest runtime from its tree when
//! `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build` asks for that. Otherwise it uses
//! the published guest runtime of its own version, acquired here exactly as a
//! release binary acquires it; a version that was never released has none,
//! and the refusal names the source build. The image set carries no guest
//! runtime, so there is no third source.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_build::artifact_acquisition::{DistributionChannel, compiled_channel};
use mvm_build::guest_bins::release::{
    ReleaseGuestRuntime, ReleaseGuestRuntimeRequest, acquire_release_guest_runtime,
    installed_guest_runtime_dirs,
};

use crate::ui;

/// The release tag a CLI version is published under.
fn release_tag(version: &str) -> String {
    format!("v{version}")
}

fn cache_root() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir())
}

fn acquire(
    version: &str,
    cache_root: &Path,
    installed_dirs: &[PathBuf],
) -> Result<ReleaseGuestRuntime> {
    let tag = release_tag(version);
    acquire_release_guest_runtime(&ReleaseGuestRuntimeRequest {
        release_url: &crate::update::release_base(&tag),
        version,
        cache_root,
        installed_dirs,
    })
    .with_context(|| format!("acquiring the guest runtime of mvmctl {tag}"))
}

/// Which guest runtime this binary will boot with, and where it came from.
/// Printed whatever the verbosity: it is the provenance of every launch that
/// follows, and the fresh-install smoke requires it from a plain `bootstrap`.
fn report(runtime: &ReleaseGuestRuntime) {
    ui::notice(&ready_line(runtime));
}

fn ready_line(runtime: &ReleaseGuestRuntime) -> String {
    let name = runtime
        .archive
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!("Guest runtime {name} ready ({}).", runtime.origin)
}

/// Make sure the published guest runtime matching the running binary's
/// version is present: installed beside the binary, cached, or fetched and
/// verified from that version's release.
pub(crate) fn prepare_for_running_binary() -> Result<ReleaseGuestRuntime> {
    let exe = std::env::current_exe().context("locating the running mvmctl")?;
    let version = crate::update::current_version();
    let runtime = acquire(version, &cache_root(), &installed_guest_runtime_dirs(&exe))
        .with_context(|| unpublished_source_build_hint(compiled_channel(), version))?;
    report(&runtime);
    Ok(runtime)
}

/// What a failed acquisition adds for a source build, whose version is
/// usually ahead of the last release and so has no published guest runtime.
fn unpublished_source_build_hint(channel: DistributionChannel, version: &str) -> String {
    match channel {
        DistributionChannel::Release => {
            format!("mvmctl {version} cannot run without the guest runtime its release ships")
        }
        DistributionChannel::Source => format!(
            "a source build of mvmctl {version} uses a published guest runtime only when that \
             version was released; assemble this checkout's with \
             `{}=build mvmctl bootstrap`",
            mvm_build::artifact_acquisition::RUNTIME_OVERLAY_ACQUIRE_MODE_ENV
        ),
    }
}

/// The published guest runtime of the running binary's version, acquired as
/// bootstrap acquires it and installed into the digest-keyed store, for an
/// explicit `build` verb that assembles one piece from it.
pub(crate) fn installed_for_running_binary(
    cache_root: &Path,
    arch: mvm_core::arch::GuestArch,
) -> Result<mvm_build::guest_runtime::GuestRuntime> {
    let release = prepare_for_running_binary()?;
    mvm_build::guest_runtime::install_release_guest_runtime(
        cache_root,
        &release.archive,
        crate::update::current_version(),
        arch,
    )
    .with_context(|| {
        format!(
            "installing the release guest runtime {}",
            release.archive.display()
        )
    })
}

/// Install only the OCI shims needed by an image launch.
pub(crate) fn prepare_oci_for_running_binary(cache_root: &Path) -> Result<()> {
    let version = crate::update::current_version();
    let arch = mvm_core::arch::GuestArch::host();
    let runtime = installed_for_running_binary(cache_root, arch)?;
    mvm_build::runtime_pieces::install_oci_guest_runtime(cache_root, version, arch, &runtime)
        .context("installing OCI guest shims from the verified release runtime")
}

/// Assemble the version-locked launch artifacts from the authenticated release.
pub(crate) fn prepare_launch_pieces_for_running_binary(cache_root: &Path) -> Result<()> {
    let release = prepare_for_running_binary()?;
    mvm_build::runtime_pieces::assemble_release_runtime_pieces(
        cache_root,
        crate::update::current_version(),
        mvm_core::arch::GuestArch::host(),
        &release.archive,
    )
    .context("assembling the release guest runtime for first launch")?;
    Ok(())
}

/// Whether `version`'s guest-runtime pieces were already assembled from its
/// release archive: the adoption record is written last, after every piece,
/// and the OCI shims are what an image launch needs beside it.
fn release_pieces_ready(
    cache_root: &Path,
    oci_cache_root: &Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
) -> bool {
    matches!(
        mvm_build::runtime_pieces::adopted_release_archive(cache_root, version, arch),
        Ok(Some(_))
    ) && mvm_build::guest_agent_build::cached_guest_binaries(oci_cache_root, version, arch)
        .is_some()
}

/// First use of a release binary: assemble this version's guest-runtime pieces
/// from the archive its release ships, once, when they are missing. The
/// archive is acquired and verified exactly as `mvmctl bootstrap` does (beside
/// the binary, cached, or downloaded and held to its digest and signature), so
/// no launch ever boots another version's pieces. A no-op for source builds,
/// which keep their explicit preparation, and once the pieces exist.
pub(crate) fn ensure_release_pieces_prepared() -> Result<()> {
    let published = compiled_channel() == DistributionChannel::Release
        && mvm_client::launch::runtime_overlay::runtime_overlay_acquire_mode()
            == mvm_client::launch::runtime_overlay::RuntimeOverlayAcquireMode::DownloadPublishedArtifact;
    if !published {
        return Ok(());
    }
    let exe = std::env::current_exe().context("locating the running mvmctl")?;
    ensure_prepared_with(
        &cache_root(),
        &mvm_core::config::oci_cache_dir(),
        crate::update::current_version(),
        mvm_core::arch::GuestArch::host(),
        &installed_guest_runtime_dirs(&exe),
        prepare_for_running_binary,
    )
}

/// [`ensure_release_pieces_prepared`] for an explicit version, architecture
/// and acquisition. `acquire` runs only when the pieces are missing; its
/// failure is reported with the version and every place the archive was
/// looked for, and nothing is assembled or recorded.
fn ensure_prepared_with(
    cache_root: &Path,
    oci_cache_root: &Path,
    version: &str,
    arch: mvm_core::arch::GuestArch,
    searched: &[PathBuf],
    acquire: impl FnOnce() -> Result<ReleaseGuestRuntime>,
) -> Result<()> {
    if release_pieces_ready(cache_root, oci_cache_root, version, arch) {
        return Ok(());
    }
    ui::notice(&format!(
        "Preparing the guest runtime of mvmctl {version} from its release archive (first use only, about a minute)..."
    ));
    let release = acquire().with_context(|| {
        let name = mvm_build::guest_bins::guest_bins_archive_name(version);
        let places: Vec<String> = searched
            .iter()
            .map(|dir| dir.display().to_string())
            .chain([
                mvm_build::guest_bins::release::release_guest_runtime_cache_dir(
                    cache_root, version,
                )
                .display()
                .to_string(),
            ])
            .collect();
        format!(
            "the guest runtime of mvmctl {version} is not prepared and {name} was not usable; \
             looked in {}",
            places.join(", ")
        )
    })?;
    mvm_build::runtime_pieces::assemble_release_runtime_pieces(
        cache_root,
        version,
        arch,
        &release.archive,
    )
    .with_context(|| {
        format!(
            "assembling the release guest runtime {} for first launch",
            release.archive.display()
        )
    })?;
    Ok(())
}

/// Fetch and verify the guest runtime the release `tag` ships, for
/// `mvmctl env update` to call before it replaces the binary. A failure here
/// leaves the installed CLI as it was, so an update never produces a CLI
/// whose own guest runtime could not be verified.
pub(crate) fn stage_for_update(tag: &str) -> Result<ReleaseGuestRuntime> {
    let version = tag.strip_prefix('v').unwrap_or(tag);
    let runtime = acquire(version, &cache_root(), &[]).with_context(|| {
        format!("refusing to update: the {tag} guest runtime is not verified; nothing was replaced")
    })?;
    report(&runtime);
    Ok(runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_VERSION: &str = "9.9.9";

    struct FirstUse {
        cache: tempfile::TempDir,
        installed: tempfile::TempDir,
    }

    impl FirstUse {
        fn new() -> Self {
            Self {
                cache: tempfile::TempDir::new().unwrap(),
                installed: tempfile::TempDir::new().unwrap(),
            }
        }

        fn oci(&self) -> PathBuf {
            self.cache.path().join("oci")
        }

        fn ensure(&self, acquired: &std::sync::atomic::AtomicUsize) -> Result<()> {
            ensure_prepared_with(
                self.cache.path(),
                &self.oci(),
                FIXTURE_VERSION,
                mvm_core::arch::GuestArch::host(),
                &[self.installed.path().to_path_buf()],
                || {
                    acquired.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    acquire_release_guest_runtime(&ReleaseGuestRuntimeRequest {
                        release_url: "file:///no-release-is-reachable",
                        version: FIXTURE_VERSION,
                        cache_root: self.cache.path(),
                        installed_dirs: &[self.installed.path().to_path_buf()],
                    })
                    .map_err(Into::into)
                },
            )
        }

        fn adopted(&self) -> Option<String> {
            mvm_build::runtime_pieces::adopted_release_archive(
                self.cache.path(),
                FIXTURE_VERSION,
                mvm_core::arch::GuestArch::host(),
            )
            .unwrap()
        }
    }

    #[test]
    fn pieces_are_not_ready_before_any_release_archive_is_adopted() {
        let first = FirstUse::new();
        assert!(!release_pieces_ready(
            first.cache.path(),
            &first.oci(),
            FIXTURE_VERSION,
            mvm_core::arch::GuestArch::host()
        ));
    }

    #[test]
    fn a_source_build_never_prepares_release_pieces_implicitly() {
        if compiled_channel() == DistributionChannel::Source {
            ensure_release_pieces_prepared().expect("a source build is a no-op here");
        }
    }

    #[test]
    fn first_use_assembles_once_and_a_second_call_does_not_touch_the_archive() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let first = FirstUse::new();
        mvm_build::guest_runtime::release_fixture::write_release_archive(
            first.installed.path(),
            FIXTURE_VERSION,
        );
        let acquired = AtomicUsize::new(0);
        first.ensure(&acquired).expect("first use assembles");
        assert_eq!(acquired.load(Ordering::SeqCst), 1);
        assert!(first.adopted().is_some(), "the adopted digest is recorded");

        std::fs::remove_dir_all(first.installed.path()).unwrap();
        first.ensure(&acquired).expect("second use is a no-op");
        assert_eq!(
            acquired.load(Ordering::SeqCst),
            1,
            "a prepared version must not read the archive again"
        );
    }

    #[test]
    fn an_archive_that_misses_its_manifest_is_refused_and_nothing_is_cached() {
        let first = FirstUse::new();
        let tampered = format!(
            "{}/lib/glibc/libmvm_host_services.so",
            mvm_core::arch::GuestArch::host()
        );
        mvm_build::guest_runtime::release_fixture::write_release_archive_tampering(
            first.installed.path(),
            FIXTURE_VERSION,
            Some(&tampered),
        );
        let acquired = std::sync::atomic::AtomicUsize::new(0);
        let err = first.ensure(&acquired).expect_err("a tampered archive");
        assert!(format!("{err:#}").contains(FIXTURE_VERSION), "{err:#}");
        assert!(first.adopted().is_none());
        assert!(!first.oci().exists(), "no OCI shims may be installed");
        assert!(
            !first.cache.path().join("guest-runtime/v1/objects").exists(),
            "a refused archive must not enter the store"
        );
    }

    #[test]
    fn a_missing_archive_refuses_naming_the_version_and_every_place_searched() {
        let first = FirstUse::new();
        let acquired = std::sync::atomic::AtomicUsize::new(0);
        let err = first.ensure(&acquired).expect_err("no archive anywhere");
        let rendered = format!("{err:#}");
        assert!(rendered.contains(FIXTURE_VERSION), "{rendered}");
        assert!(
            rendered.contains("mvm-guest-bins-v9.9.9.tar.gz"),
            "{rendered}"
        );
        assert!(
            rendered.contains(&first.installed.path().display().to_string()),
            "{rendered}"
        );
        assert!(
            rendered.contains(&first.cache.path().display().to_string()),
            "{rendered}"
        );
        assert!(first.adopted().is_none());
    }

    #[test]
    fn concurrent_first_use_leaves_one_valid_set_of_pieces() {
        let first = FirstUse::new();
        mvm_build::guest_runtime::release_fixture::write_release_archive(
            first.installed.path(),
            FIXTURE_VERSION,
        );
        let acquired = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let a = scope.spawn(|| first.ensure(&acquired));
            let b = scope.spawn(|| first.ensure(&acquired));
            a.join().unwrap().expect("first caller");
            b.join().unwrap().expect("second caller");
        });
        assert!(first.adopted().is_some());
        let arch = mvm_core::arch::GuestArch::host().to_string();
        mvm_fs::overlay::RuntimeOverlayResolver::new(
            first.cache.path().to_path_buf(),
            FIXTURE_VERSION.to_string(),
        )
        .resolve(&arch)
        .expect("the overlay both callers raced to build is valid");
        assert!(release_pieces_ready(
            first.cache.path(),
            &first.oci(),
            FIXTURE_VERSION,
            mvm_core::arch::GuestArch::host()
        ));
    }

    #[test]
    fn a_version_is_published_under_its_v_tag() {
        assert_eq!(release_tag("0.23.1"), "v0.23.1");
        assert_eq!(release_tag("0.24.0-rc.1"), "v0.24.0-rc.1");
    }

    /// A source build's version is usually unreleased; when its published
    /// runtime cannot be acquired, the refusal names the source build rather
    /// than falling back to anything.
    /// `scripts/smoke-fresh-install.sh` greps for this exact text to prove a
    /// release archive adopted the guest runtime staged beside it.
    #[test]
    fn the_ready_line_names_the_archive_and_where_it_came_from() {
        let runtime = ReleaseGuestRuntime {
            archive: PathBuf::from("/r/guest-runtime/mvm-guest-bins-v9.9.9.tar.gz"),
            manifest: mvm_build::guest_bins::GuestBinsManifest {
                schema_version: mvm_build::guest_bins::GUEST_BINS_MANIFEST_SCHEMA,
                version: "9.9.9".to_string(),
                guest_source_fingerprint: "a".repeat(64),
                sdk_cdylib_source_fingerprint: "b".repeat(64),
                source: mvm_build::image_source::RepoIdentity {
                    commit: mvm_core::image_set::GitCommit::new("c".repeat(40)).unwrap(),
                    worktree: mvm_core::image_set::WorktreeState::Clean,
                },
                files: Default::default(),
                assemblies: Default::default(),
            },
            origin: mvm_build::guest_bins::release::ReleaseGuestRuntimeOrigin::Installed,
        };
        assert_eq!(
            ready_line(&runtime),
            "Guest runtime mvm-guest-bins-v9.9.9.tar.gz ready (installed beside mvmctl)."
        );
    }

    #[test]
    fn an_unpublished_source_build_is_pointed_at_its_own_tree() {
        let hint = unpublished_source_build_hint(DistributionChannel::Source, "9.9.9");
        assert!(
            hint.contains("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap"),
            "{hint}"
        );
        let release = unpublished_source_build_hint(DistributionChannel::Release, "9.9.9");
        assert!(!release.contains("ACQUIRE_MODE"), "{release}");
    }

    #[test]
    fn a_missing_published_runtime_refuses_and_names_the_source_build() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let empty = tempfile::TempDir::new().unwrap();
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            format!("file://{}", empty.path().display()),
        );
        let home = tempfile::TempDir::new().unwrap();
        env.set("HOME", home.path().to_string_lossy().into_owned());
        env.set(
            "MVM_HOME",
            home.path().join("state").to_string_lossy().into_owned(),
        );
        if compiled_channel() == DistributionChannel::Source {
            let err = prepare_for_running_binary().expect_err("no runtime is published here");
            assert!(
                format!("{err:#}").contains("MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build"),
                "{err:#}"
            );
        }
    }

    #[test]
    fn an_update_to_a_release_without_a_runtime_refuses_before_replacing_anything() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let empty = tempfile::TempDir::new().unwrap();
        env.set(
            "MVM_UPDATE_DOWNLOAD_URL",
            format!("file://{}", empty.path().display()),
        );
        let home = tempfile::TempDir::new().unwrap();
        env.set("HOME", home.path().to_string_lossy().into_owned());
        env.set(
            "MVM_HOME",
            home.path().join("state").to_string_lossy().into_owned(),
        );

        let err = stage_for_update("v9.9.9").expect_err("no published runtime means no update");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("refusing to update") && rendered.contains("nothing was replaced"),
            "{rendered}"
        );
    }
}
