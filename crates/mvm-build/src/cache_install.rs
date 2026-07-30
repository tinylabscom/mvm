//! How artifacts enter a cache root.
//!
//! Two conventions live here because both are shared by every cached
//! artifact (the builder VM image, the runtime overlay, the universal
//! initramfs) and both were previously reimplemented per artifact:
//!
//! 1. **The cross-root seed.** An isolated session (a worktree pointing
//!    `MVM_HOME` at a tempdir) can populate its own cache root from the
//!    host's shared one instead of rebuilding an expensive artifact. This
//!    module owns the only derivation of that shared root, so the set of
//!    places that can read `$HOME` while `MVM_HOME` is set stays exactly
//!    one — see the `check-test-home-isolation` gate.
//! 2. **The staging convention.** Installs stage into a sibling
//!    `<arch>.tmp.<pid>` directory and rename it into place, so a crash
//!    never leaves a half-written artifact where a resolver can find it.
//!    The flip side is that a killed install orphans its staging dir, so
//!    installers reap abandoned ones as they go.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// The cache root of the *default* mvm home (`$HOME/.mvm/cache`),
/// deliberately ignoring the `MVM_HOME` override.
///
/// This is the single call site for that resolver in the whole workspace.
/// Keeping it here means a new cross-root seed is a visible change to this
/// module rather than a fresh `$HOME` read buried in an artifact module —
/// which matters because a test that isolates only `MVM_HOME` still reads
/// the developer's real cache through this path.
pub(crate) fn default_cache_root() -> PathBuf {
    PathBuf::from(mvm_core::config::default_mvm_cache_dir())
}

/// Populate `target_root` from `default_root` after a resolve miss.
///
/// Returns whether anything was installed, so the caller can retry its
/// resolve exactly once and otherwise surface its original error unchanged.
///
/// A miss in the *default* root is not an error — seeding is opportunistic,
/// and a host that has never built the artifact simply has nothing to give.
/// That is why `resolve_default` yields an `Option` rather than a `Result`:
/// the "nothing to seed" outcome is in the type instead of relying on every
/// caller to remember to swallow it. An `install` failure, by contrast, means
/// the target cache may be half-populated and does propagate.
pub(crate) fn seed_on_miss<S, E>(
    target_root: &Path,
    default_root: &Path,
    resolve_default: impl FnOnce(&Path) -> Option<S>,
    install: impl FnOnce(S) -> Result<(), E>,
) -> Result<bool, E> {
    if target_root == default_root {
        return Ok(false);
    }
    let Some(source) = resolve_default(default_root) else {
        return Ok(false);
    };
    install(source)?;
    Ok(true)
}

/// Name of this process's staging directory for `arch`.
///
/// The pid disambiguates concurrent installs. Two installs in the same
/// process race on the post-staging rename, where the second one wins —
/// the same semantics as installing twice.
pub(crate) fn staging_dir_name(arch: &str) -> String {
    format!("{}.tmp.{}", arch, std::process::id())
}

/// How long an abandoned staging directory must sit before an install reaps
/// it. Staging is a handful of file copies, so anything this old belongs to a
/// process that died before its rename.
const STALE_STAGING_AGE: Duration = Duration::from_secs(6 * 60 * 60);

/// Remove staging directories for `arch` under `parent` that a previous run
/// abandoned.
///
/// Age is the liveness signal rather than the pid embedded in the name: a
/// portable pid check needs `libc` or `/proc`, and pid reuse makes it
/// unreliable in the one direction that matters. Judging by age can only ever
/// be wrong by leaving litter one cycle longer, never by deleting a live
/// install's staging directory.
///
/// Best-effort by design — reaping litter must never fail an install, so
/// every error here is dropped.
pub(crate) fn reap_stale_staging(parent: &Path, arch: &str) {
    reap_staging_older_than(parent, arch, STALE_STAGING_AGE);
}

/// The age threshold is a parameter so tests can drive the real selection
/// logic without backdating filesystem timestamps.
fn reap_staging_older_than(parent: &Path, arch: &str, max_age: Duration) {
    let ours = staging_dir_name(arch);
    let prefix = format!("{arch}.tmp.");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name == ours || !name.starts_with(&prefix) {
            continue;
        }
        let abandoned = entry
            .metadata()
            .ok()
            .filter(|meta| meta.is_dir())
            .and_then(|meta| meta.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= max_age);
        if abandoned {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_on_miss_declines_when_target_is_the_default_root() {
        let mut installed = false;
        let seeded = seed_on_miss(
            Path::new("/same"),
            Path::new("/same"),
            |_| Some(()),
            |()| {
                installed = true;
                Ok::<(), ()>(())
            },
        )
        .unwrap();
        assert!(!seeded);
        assert!(!installed, "must not install into the root it reads from");
    }

    #[test]
    fn seed_on_miss_declines_when_the_default_root_has_nothing() {
        let seeded = seed_on_miss(
            Path::new("/target"),
            Path::new("/default"),
            |_| None::<()>,
            |()| Ok::<(), ()>(()),
        )
        .unwrap();
        assert!(!seeded, "a default-root miss is not an error");
    }

    #[test]
    fn seed_on_miss_installs_and_reports_success() {
        let mut seen = None;
        let seeded = seed_on_miss(
            Path::new("/target"),
            Path::new("/default"),
            |root| Some(root.to_path_buf()),
            |root| {
                seen = Some(root);
                Ok::<(), ()>(())
            },
        )
        .unwrap();
        assert!(seeded);
        assert_eq!(seen.as_deref(), Some(Path::new("/default")));
    }

    #[test]
    fn seed_on_miss_propagates_install_failure() {
        let result = seed_on_miss(
            Path::new("/target"),
            Path::new("/default"),
            |_| Some(()),
            |()| Err::<(), &str>("disk full"),
        );
        assert_eq!(result.unwrap_err(), "disk full");
    }

    #[test]
    fn staging_dir_name_is_arch_scoped_and_pid_scoped() {
        let name = staging_dir_name("aarch64");
        assert!(name.starts_with("aarch64.tmp."));
        assert!(name.ends_with(&std::process::id().to_string()));
    }

    #[test]
    fn reap_leaves_fresh_and_foreign_dirs_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let ours = tmp.path().join(staging_dir_name("aarch64"));
        let fresh_other = tmp.path().join("aarch64.tmp.999999");
        let other_arch = tmp.path().join("x86_64.tmp.999999");
        let real = tmp.path().join("aarch64");
        for dir in [&ours, &fresh_other, &other_arch, &real] {
            std::fs::create_dir_all(dir).unwrap();
        }

        reap_stale_staging(tmp.path(), "aarch64");

        assert!(ours.is_dir(), "our own staging dir must survive");
        assert!(fresh_other.is_dir(), "a fresh orphan may still be in use");
        assert!(other_arch.is_dir(), "another arch is not ours to reap");
        assert!(
            real.is_dir(),
            "the installed artifact must never be touched"
        );
    }

    #[test]
    fn reap_removes_an_abandoned_staging_dir_with_its_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let stale = tmp.path().join("aarch64.tmp.999999");
        let ours = tmp.path().join(staging_dir_name("aarch64"));
        let real = tmp.path().join("aarch64");
        std::fs::create_dir_all(stale.join("nested")).unwrap();
        std::fs::write(stale.join("nested").join("overlay.ext4"), b"partial").unwrap();
        std::fs::create_dir_all(&ours).unwrap();
        std::fs::create_dir_all(&real).unwrap();

        // Everything is newly created, so a zero threshold makes every
        // candidate eligible — proving selection is by name, not by age alone.
        reap_staging_older_than(tmp.path(), "aarch64", Duration::ZERO);

        assert!(!stale.exists(), "an abandoned staging dir must be reaped");
        assert!(ours.is_dir(), "our own staging dir is never eligible");
        assert!(
            real.is_dir(),
            "the installed artifact must never be touched"
        );
    }

    #[test]
    fn the_shipped_threshold_spares_a_dir_that_was_just_created() {
        let tmp = tempfile::tempdir().unwrap();
        let fresh = tmp.path().join("aarch64.tmp.999999");
        std::fs::create_dir_all(&fresh).unwrap();

        reap_stale_staging(tmp.path(), "aarch64");

        assert!(
            fresh.is_dir(),
            "a concurrent install's staging dir must survive the real threshold"
        );
    }
}
