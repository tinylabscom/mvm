//! Where the builder finds its host helper binaries relative to the running
//! process: the network endpoint beside the host binaries, and the cargo target
//! roots a libkrun supervisor may have been built into.

#[cfg(feature = "builder-libkrun")]
use std::path::Path;
use std::path::PathBuf;

use mvm_vmm::host::aux_bin::HostProcess;

/// Whether `candidate` predates the running executable.
///
/// The endpoint is a separate binary that `machine run` does not build, so a
/// copy left by an older checkout sits on disk and is picked up in preference
/// to building a current one. A guest and a host from different builds then
/// speak different protocols, and the only symptom is a framing error whose
/// length field decodes to ASCII from the wrong wire format.
///
/// Modification time is the cheap comparison that catches it: both binaries
/// come out of the same workspace, so an endpoint older than the `mvmctl`
/// running it cannot have been built from this source. Unknowable times mean
/// no opinion — rebuild rather than refuse, since a false stale reading costs
/// a build and a false fresh one costs a mystery.
pub(crate) fn endpoint_predates_running_exe(candidate: &std::path::Path) -> bool {
    let modified = |p: &std::path::Path| p.metadata().and_then(|m| m.modified()).ok();
    let Some(exe) = std::env::current_exe().ok().as_deref().and_then(modified) else {
        return false;
    };
    let Some(cand) = modified(candidate) else {
        return true;
    };
    cand < exe
}

/// A current `mvm-network-endpoint` in `host`'s host binary directory.
pub(crate) fn endpoint_in_host_binary_dir(host: &HostProcess) -> Option<PathBuf> {
    host.binary_named("mvm-network-endpoint")
        .filter(|candidate| !endpoint_predates_running_exe(candidate))
}

#[cfg(feature = "builder-libkrun")]
pub(crate) fn supervisor_target_roots(workspace_root: &Path) -> Vec<PathBuf> {
    supervisor_target_roots_for(workspace_root, &HostProcess::current())
}

#[cfg(feature = "builder-libkrun")]
fn supervisor_target_roots_for(workspace_root: &Path, host: &HostProcess) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from) {
        roots.push(if target_dir.is_absolute() {
            target_dir
        } else {
            workspace_root.join(target_dir)
        });
    }
    roots.push(workspace_root.join("target"));
    if let Some(exe_dir) = host.binary_dir()
        && let Some(target_dir) = exe_dir.parent()
        && target_dir.file_name().is_some_and(|name| name == "target")
    {
        roots.push(target_dir.to_path_buf());
    }
    let mut deduped = Vec::new();
    for root in roots {
        let normalized = root.canonicalize().unwrap_or(root);
        if !deduped.iter().any(|existing| existing == &normalized) {
            deduped.push(normalized);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "builder-libkrun")]
    use mvm_core::util::test_env::TestEnv;
    use tempfile::TempDir;

    #[cfg(feature = "builder-libkrun")]
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn the_network_endpoint_is_found_in_a_declared_host_binary_dir() {
        let declared = TempDir::new().unwrap();
        let host = HostProcess::undeclared().with_binary_dir(declared.path());
        assert_eq!(endpoint_in_host_binary_dir(&host), None);

        // Written after the test binary was linked, so it is not stale.
        std::fs::write(declared.path().join("mvm-network-endpoint"), b"bin").unwrap();

        assert_eq!(
            endpoint_in_host_binary_dir(&host),
            Some(declared.path().join("mvm-network-endpoint"))
        );
    }

    #[test]
    #[cfg(feature = "builder-libkrun")]
    fn a_declared_cargo_profile_dir_contributes_its_target_root() {
        let _env_lock = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.remove("CARGO_TARGET_DIR");
        let scratch = TempDir::new().unwrap();
        let profile_dir = scratch.path().join("target").join("release");
        std::fs::create_dir_all(&profile_dir).unwrap();
        let host = HostProcess::undeclared().with_binary_dir(&profile_dir);

        let roots = supervisor_target_roots_for(Path::new("/nonexistent-workspace"), &host);

        let expected = scratch.path().join("target").canonicalize().unwrap();
        assert!(roots.contains(&expected), "{roots:?}");
    }

    /// The regression this exists for. `machine run` does not build the
    /// endpoint, so a copy from an older checkout is found first and used
    /// silently; the guest and host then speak different protocols and the
    /// only symptom is a frame-length field that decodes to ASCII.
    #[test]
    fn an_endpoint_older_than_the_running_exe_is_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        let old = dir.path().join("mvm-network-endpoint");
        std::fs::write(&old, b"pre-cutover").expect("write");
        // Backdate well past any plausible clock skew between the two files.
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 86_400);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .expect("open")
            .set_modified(long_ago)
            .expect("backdate");

        assert!(
            endpoint_predates_running_exe(&old),
            "an endpoint a week older than the running binary must read as stale"
        );
    }

    /// The companion, so the check cannot pass by calling everything stale:
    /// a binary newer than the running one is used as-is.
    #[test]
    fn an_endpoint_newer_than_the_running_exe_is_not_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fresh = dir.path().join("mvm-network-endpoint");
        std::fs::write(&fresh, b"current").expect("write");
        let soon = std::time::SystemTime::now() + std::time::Duration::from_secs(600);
        std::fs::File::options()
            .write(true)
            .open(&fresh)
            .expect("open")
            .set_modified(soon)
            .expect("postdate");

        assert!(
            !endpoint_predates_running_exe(&fresh),
            "an endpoint newer than the running binary must be used as-is"
        );
    }

    /// A path that cannot be stat'd has no usable time. Reading that as stale
    /// costs a rebuild; reading it as fresh costs a protocol mismatch nobody
    /// can diagnose, so it fails towards the rebuild.
    #[test]
    fn an_unstattable_endpoint_reads_as_stale() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(endpoint_predates_running_exe(&dir.path().join("absent")));
    }
}
