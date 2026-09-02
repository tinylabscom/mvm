//! Process-resident global state shared across the accept loop, the signal
//! handlers, the boot-sequence background threads, and the request handlers.
//! Kept in one place because every one of these statics is written from one
//! module and read from at least one other.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use mvm_agentd::entrypoint::ValidatedEntrypoint;
use mvm_agentd::extension::ValidatedExtension;
use mvm_agentd::worker_pool::WorkerPool;

use crate::config::DEFAULT_SAMPLE_INTERVAL_SECS;

/// Set on first SIGTERM/SIGINT. The accept loop polls this and
/// breaks when it flips.
pub(crate) static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Process-resident VMGenID reseeder. Seeded with the all-zero baseline so the
/// first non-zero token delivered on a `PostRestore` resume counts as a
/// clone-divergence and reseeds the CSPRNG. The reseeder's state rides the VM
/// memory snapshot, so two clones restored from one snapshot both diverge from
/// the captured value when the host hands each a distinct fresh token.
pub(crate) static GENID_RESEEDER: Mutex<mvm_agentd::genid::GenIdReseeder> = Mutex::new(
    mvm_agentd::genid::GenIdReseeder::new([0u8; mvm_core::crypto::vmgenid::GENID_BYTES]),
);

/// Dispatch a token delivered on `PostRestore` to the resident reseeder. A
/// poisoned lock degrades to "no rotation" rather than panicking the handler —
/// the remount/restart work still needs to run.
pub(crate) fn reseed_on_post_restore(
    token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
) -> mvm_agentd::genid::GenIdAction {
    match GENID_RESEEDER.lock() {
        Ok(mut r) => r.on_post_restore_token(token),
        Err(_) => mvm_agentd::genid::GenIdAction::Unchanged,
    }
}

/// Counts shutdown signals delivered. ≥2 means the operator has
/// asked twice — escalate to `_exit` and skip the drain.
pub(crate) static SHUTDOWN_SIGNAL_COUNT: AtomicU8 = AtomicU8::new(0);

/// Set by `on_reload_signal` (SIGHUP). The accept loop polls this
/// between iterations and, when set, re-reads
/// the config file and applies the hot-reloadable subset.
/// Distinct from `SHUTDOWN_REQUESTED` so a reload doesn't terminate
/// the agent.
pub(crate) static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Path of the config file the agent loaded at boot. Captured by
/// `parse_config` so the SIGHUP handler can re-read the same file
/// even when the operator launched with `--config <path>`.
pub(crate) static AGENT_CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Current value of the busy threshold (f64 bits) seen by the
/// monitoring loop. Updated atomically by `apply_reload`.
pub(crate) static HOT_BUSY_THRESHOLD_BITS: AtomicU64 = AtomicU64::new(0);

/// Current sample interval in seconds, updated atomically by
/// `apply_reload`. Initialized to a sane default until main() runs.
pub(crate) static HOT_SAMPLE_INTERVAL_SECS: AtomicU64 =
    AtomicU64::new(DEFAULT_SAMPLE_INTERVAL_SECS);

/// Default grace period for `shutdown_subsystems` to wait between
/// "shut down requested" and forcing exit. Mirrors the cold-path
/// `CallCaps::v1().kill_grace_period * 2 + slack` so a typical
/// in-flight call has time to finish + the worker pool can SIGTERM
/// → grace → SIGKILL idle workers cleanly.
pub(crate) const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Validation result captured once at boot. The held `ValidatedEntrypoint`
/// keeps an open file handle to the wrapper binary so spawn-time uses
/// `/proc/self/fd/<n>` (Linux) instead of re-resolving the path, defeating
/// any TOCTOU between validation and spawn.
pub(crate) static VALIDATED_ENTRYPOINT: OnceLock<Result<ValidatedEntrypoint, String>> =
    OnceLock::new();

/// Optional extension executables validated from the authenticated activation
/// message after their read-only artifacts are mounted.
pub(crate) static VALIDATED_EXTENSIONS: OnceLock<Result<Vec<ValidatedExtension>, String>> =
    OnceLock::new();

/// One in-flight `RunEntrypoint` per VM — applies to the cold
/// path only. When `WARM_POOL.is_some()`, this lock is bypassed; the
/// new invariant is "one in-flight call per worker, ≤ `pool_size`
/// concurrent". Concurrent callers under cold-tier still
/// get `EntrypointEvent::Error { kind: Busy }` immediately; warm-tier
/// callers queue FIFO up to `max_queue_depth` and get `Busy` on
/// overflow.
pub(crate) static RUN_ENTRYPOINT_LOCK: Mutex<()> = Mutex::new(());

/// Warm-process worker pool, populated at boot from
/// `/etc/mvm/runtime.json`. `None` means cold-tier
/// behavior — the existing single-call path. `Some(_)` activates
/// the warm-process branch in `handle_run_entrypoint` and the
/// thread-per-connection accept-loop.
pub(crate) static WARM_POOL: OnceLock<Option<Arc<WorkerPool>>> = OnceLock::new();
