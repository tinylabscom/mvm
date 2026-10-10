//! The guest runtime a downloaded `mvmctl` ships with.
//!
//! Each CLI release publishes the `mvm-guest-bins` archive beside its
//! tarballs, signed under the same release identity. Two commands acquire it:
//! `mvmctl bootstrap` on a release binary, for the binary's own version, and
//! `mvmctl env update`, for the version it is about to install, before the
//! running binary is touched. The acquisition itself — installed copy, cache,
//! or download held to its digest and then its signature — is
//! [`mvm_build::guest_bins::release`].
//!
//! A source checkout builds its guest runtime from the tree instead, so
//! nothing here runs for one.

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

fn report(runtime: &ReleaseGuestRuntime) {
    let name = runtime
        .archive
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    ui::success(&format!("Guest runtime {name} ready ({}).", runtime.origin));
}

/// Make sure the release guest runtime matching the running binary is
/// present. A source build has nothing to acquire and returns `None`.
pub(crate) fn prepare_for_running_binary() -> Result<Option<ReleaseGuestRuntime>> {
    if compiled_channel() != DistributionChannel::Release {
        return Ok(None);
    }
    let exe = std::env::current_exe().context("locating the running mvmctl")?;
    let runtime = acquire(
        crate::update::current_version(),
        &cache_root(),
        &installed_guest_runtime_dirs(&exe),
    )?;
    report(&runtime);
    Ok(Some(runtime))
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

    #[test]
    fn a_source_build_acquires_nothing() {
        if compiled_channel() == DistributionChannel::Source {
            assert!(prepare_for_running_binary().unwrap().is_none());
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
            home.path().join(".mvm").to_string_lossy().into_owned(),
        );

        let err = stage_for_update("v9.9.9").expect_err("no published runtime means no update");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("refusing to update") && rendered.contains("nothing was replaced"),
            "{rendered}"
        );
    }
}
