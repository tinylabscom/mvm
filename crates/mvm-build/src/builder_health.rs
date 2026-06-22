//! Per-host builder-VM health cache.
//!
//! On a host where libkrun can't create its builder VM — e.g. the
//! `KVM_SET_USER_MEMORY_REGION` EINVAL defect on some Linux kernels —
//! the auto-fallback would otherwise pay a doomed libkrun attempt on *every*
//! build before switching to qemu. This records a short-lived marker so
//! subsequent builds skip straight to the qemu builder. The marker self-heals
//! after a TTL (a transient failure, or a libkrun upgrade, re-probes the next
//! day), and an explicit `--builder libkrun` that succeeds clears it.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::builder_backend_select::BuilderBackendChoice;

/// How long a "libkrun builder unavailable" marker is honoured before it is
/// treated as stale and re-probed. Long enough to spare a reliably-broken host
/// the repeated doomed attempt across a dev session; short enough that a
/// transient failure self-heals by the next day.
const MARKER_TTL_SECS: u64 = 24 * 60 * 60;

fn marker_path() -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_cache_dir())
        .join("builder-health")
        .join("libkrun-unavailable")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pure freshness check, lifted out so the TTL boundary is unit-testable
/// without touching the clock or the filesystem.
fn marker_is_fresh(recorded_at_secs: u64, now: u64) -> bool {
    now.saturating_sub(recorded_at_secs) < MARKER_TTL_SECS
}

/// Is there a fresh "libkrun can't build here" marker? A stale marker is
/// removed and reported absent so the host re-probes libkrun.
pub fn libkrun_marked_unavailable() -> bool {
    let path = marker_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return false;
    };
    let recorded = contents.trim().parse::<u64>().unwrap_or(0);
    if marker_is_fresh(recorded, now_secs()) {
        true
    } else {
        let _ = std::fs::remove_file(&path);
        false
    }
}

/// Record that an auto-detected libkrun builder failed to create its VM here.
/// Best-effort: a write failure just means the next build re-attempts libkrun.
fn record_libkrun_unavailable() {
    let path = marker_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&path, now_secs().to_string());
}

/// Clear the marker — libkrun built successfully, so it has recovered here (or
/// was never broken).
fn clear_libkrun_marker() {
    let _ = std::fs::remove_file(marker_path());
}

/// Fold one builder attempt's outcome into the host health cache. Only libkrun
/// outcomes move the marker: a VMM-level libkrun failure sets it; a libkrun
/// success clears it. Other backends never touch it.
pub fn note_attempt_outcome(choice: BuilderBackendChoice, succeeded: bool) {
    if choice != BuilderBackendChoice::Libkrun {
        return;
    }
    if succeeded {
        clear_libkrun_marker();
    } else {
        record_libkrun_unavailable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    fn isolated_cache() -> (TestEnv, tempfile::TempDir) {
        let scratch = tempfile::TempDir::new().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_CACHE_DIR", scratch.path().join(".cache"));
        (env, scratch)
    }

    #[test]
    fn fresh_within_ttl_stale_beyond() {
        assert!(marker_is_fresh(1_000, 1_000));
        assert!(marker_is_fresh(1_000, 1_000 + MARKER_TTL_SECS - 1));
        assert!(!marker_is_fresh(1_000, 1_000 + MARKER_TTL_SECS));
        assert!(!marker_is_fresh(1_000, 1_000 + MARKER_TTL_SECS + 10));
        // A clock that went backwards must not read as ancient (saturating).
        assert!(marker_is_fresh(1_000, 500));
    }

    #[test]
    fn libkrun_failure_sets_marker_success_clears_it() {
        let (_env, _scratch) = isolated_cache();
        assert!(!libkrun_marked_unavailable(), "no marker initially");

        note_attempt_outcome(BuilderBackendChoice::Libkrun, false);
        assert!(libkrun_marked_unavailable(), "libkrun VMM failure marks it");

        note_attempt_outcome(BuilderBackendChoice::Libkrun, true);
        assert!(!libkrun_marked_unavailable(), "libkrun success clears it");
    }

    #[test]
    fn non_libkrun_outcomes_never_touch_marker() {
        let (_env, _scratch) = isolated_cache();
        note_attempt_outcome(BuilderBackendChoice::Libkrun, false);
        // A qemu success after a libkrun failure must leave the marker intact —
        // the fallback worked, libkrun is still broken here.
        note_attempt_outcome(BuilderBackendChoice::Qemu, true);
        assert!(libkrun_marked_unavailable());
        // A Vz failure (macOS) is unrelated and must not set the libkrun marker.
        note_attempt_outcome(BuilderBackendChoice::Libkrun, true); // reset
        note_attempt_outcome(BuilderBackendChoice::Vz, false);
        assert!(!libkrun_marked_unavailable());
    }

    #[test]
    fn stale_marker_is_removed_and_reported_absent() {
        let (_env, _scratch) = isolated_cache();
        let path = marker_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "1").unwrap(); // unix ts 1 — ancient
        assert!(!libkrun_marked_unavailable());
        assert!(!path.exists(), "stale marker removed on read");
    }
}
