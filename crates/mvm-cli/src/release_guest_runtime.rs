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
