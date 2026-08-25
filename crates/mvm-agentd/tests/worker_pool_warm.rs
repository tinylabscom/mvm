//! Integration tests for the warm-process worker pool.
//!
//! Drives a real `WorkerPool` against the `fake-runner` test binary
//! to exercise the recycling paths (call-count, wrapper crash) and
//! the FIFO queue. Tests run on macOS dev hosts and Linux equally —
//! the only Linux-specific bit is `/proc/<pid>/statm` RSS sampling,
//! which the cross-platform tests in this file don't depend on. RSS
//! recycling lives in the Linux-gated test below.
//!
//! These tests never touch `handle_run_entrypoint` or the cold-tier
//! lock; the cold path is unaffected.

use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mvm_agentd::entrypoint::ValidatedEntrypoint;
use mvm_agentd::lifecycle_hooks::ReadinessConfig;
use mvm_agentd::runtime_config::{InProcessMode, WarmProcessConfig};
use mvm_agentd::worker_pool::{DispatchError, DispatchOutcome, SlotSnapshot, WorkerPool};
use mvm_agentd::worker_protocol::WorkerOutcome;

/// Cargo sets `CARGO_BIN_EXE_<name>` at compile time for integration
/// tests, pointing at the built test binary.
const FAKE_RUNNER: &str = env!("CARGO_BIN_EXE_fake-runner");

fn validated_for_fake_runner() -> ValidatedEntrypoint {
    let path = PathBuf::from(FAKE_RUNNER);
    let file = File::open(&path).expect("fake-runner exists");
    ValidatedEntrypoint {
        resolved: path,
        file,
        use_resolved_path: false,
    }
}

fn cfg(pool_size: usize, max_calls: u64, max_rss_mb: u64) -> WarmProcessConfig {
    WarmProcessConfig {
        max_calls_per_worker: max_calls,
        max_rss_mb,
        pool_size,
        in_process: InProcessMode::Serial,
        max_queue_depth: None,
    }
}

fn start_pool(cfg: WarmProcessConfig) -> Arc<WorkerPool> {
    start_pool_with_behavior(cfg, None)
}

fn start_pool_with_behavior(cfg: WarmProcessConfig, behavior: Option<&str>) -> Arc<WorkerPool> {
    let entry = Arc::new(validated_for_fake_runner());
    let env: Vec<(String, String)> = behavior
        .map(|b| vec![("MVM_FAKE_RUNNER_BEHAVIOR".to_string(), b.to_string())])
        .unwrap_or_default();
    let pool = WorkerPool::start(cfg, entry, env).expect("pool start");
    // The pool now starts in `NotReady` state. These integration
    // tests don't exercise the readiness gate (covered separately in
    // unit + integration tests for the probe itself); mark it ready
    // immediately so the existing dispatch round-trips behave as they
    // did before the readiness gate existed.
    pool.mark_ready();
    pool
}

fn dispatch(pool: &Arc<WorkerPool>, payload: &[u8]) -> DispatchOutcome {
    pool.dispatch(payload.to_vec(), CALL_HANG_GUARD_SECS, Vec::new())
        .expect("dispatch returns outcome")
}

/// Per-call timeout for dispatches whose test asserts a *result* — ordering,
/// recycling, which slot served it — rather than a duration.
///
/// Not a budget. Sizing it as a small multiple of the expected call is what
/// made this file flaky: `idle_timeout_skips_busy_workers` gave a `slow_secs=2`
/// worker a 5s timeout and failed at 5.099s under a loaded run, and
/// `fifo_queue_serializes_callers` is tighter still by construction — five
/// calls serialize through a one-slot pool, so the last caller's budget has to
/// cover the four ahead of it, and each was given the same 5s.
///
/// Reached only when a call never returns, which is a hang rather than a slow
/// host. Never tune it toward "what seems fast enough"; the only test here that
/// asserts a timeout *occurs* is the readiness-probe one, which sets its own.
const CALL_HANG_GUARD_SECS: u64 = 120;

/// Block until `cond` holds, or fail the test.
///
/// A fixed sleep used as a readiness wait is wrong in both directions:
/// too short and the test fails on a loaded host for no reason, too long
/// and every run pays the worst case. The deadline here is generous
/// because it is only ever reached when something is genuinely broken;
/// the poll interval is what sets the common-case cost.
fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    const LIMIT: Duration = Duration::from_secs(10);
    const POLL: Duration = Duration::from_millis(5);
    let deadline = Instant::now() + LIMIT;
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(POLL);
    }
    panic!("timed out after {LIMIT:?} waiting for {what}");
}

/// True once at least one slot is mid-call.
fn any_slot_busy(pool: &Arc<WorkerPool>) -> bool {
    pool.snapshot()
        .iter()
        .any(|s| matches!(s, SlotSnapshot::Busy))
}

fn idle_pid(pool: &Arc<WorkerPool>) -> u32 {
    let snap = pool.snapshot();
    snap.iter()
        .find_map(|s| match s {
            SlotSnapshot::Idle { pid, .. } => Some(*pid),
            _ => None,
        })
        .expect("at least one idle slot")
}

fn idle_call_count(pool: &Arc<WorkerPool>, pid: u32) -> u64 {
    let snap = pool.snapshot();
    snap.iter()
        .find_map(|s| match s {
            SlotSnapshot::Idle {
                pid: p, call_count, ..
            } if *p == pid => Some(*call_count),
            _ => None,
        })
        .unwrap_or(0)
}

#[test]
fn warm_process_round_trip_pid_stable() {
    // SAFETY: tests in this binary run sequentially? No — Cargo runs
    // them in parallel by default. Each test that sets env vars must
    // either coordinate or use a separate behavior flag. For "ok"
    // (default) we don't need to set anything.
    let pool = start_pool(cfg(1, 100, 1024));
    let pid_before = idle_pid(&pool);

    let out1 = dispatch(&pool, b"hello");
    assert_eq!(out1.stdout, b"hello");
    assert!(matches!(out1.outcome, WorkerOutcome::Exit { code: 0 }));

    let out2 = dispatch(&pool, b"world");
    assert_eq!(out2.stdout, b"world");
    assert!(matches!(out2.outcome, WorkerOutcome::Exit { code: 0 }));

    assert_eq!(idle_pid(&pool), pid_before, "PID stable across calls");
    assert_eq!(idle_call_count(&pool, pid_before), 2);
}

#[test]
fn warm_process_emits_control_records_through_pool() {
    // A wrapper that emits one envelope-style control
    // record per call should round-trip through the pool intact.
    // Stderr stays as opaque user output (containing the literal
    // `MVMFORGE_ENVELOPE:` token the fake runner writes there) —
    // proving the host can no longer be tricked into reparsing
    // stderr as a structured envelope, since envelopes now arrive
    // through the dedicated `controls` channel.
    let pool = start_pool_with_behavior(cfg(1, 100, 1024), Some("emit_control"));

    let out = dispatch(&pool, b"payload");
    assert!(matches!(out.outcome, WorkerOutcome::Exit { code: 0 }));
    assert_eq!(out.controls.len(), 1, "expected one control record");
    assert!(
        out.controls[0].header_json.contains(r#""kind":"envelope""#),
        "control header was {:?}",
        out.controls[0].header_json
    );
    assert!(out.controls[0].payload.is_empty());
    // Stderr passthrough: the literal `MVMFORGE_ENVELOPE:` is
    // delivered as bytes, not parsed as an envelope by the host.
    assert!(
        out.stderr
            .starts_with(b"MVMFORGE_ENVELOPE: this-must-not-be-parsed"),
        "stderr should pass through verbatim, got {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_warm_worker_cannot_claim_the_agent_namespace() {
    // A warm worker *is* the workload, so its control records carry the same
    // authorship fd 3's do, and the same refusal has to apply. Were it to
    // pass, a workload could mint a gap marker and a verifier downstream
    // would bless a chain skipping output it never saw.
    let pool = start_pool_with_behavior(cfg(1, 100, 1024), Some("forge_control"));

    let out = dispatch(&pool, b"payload");
    assert!(matches!(out.outcome, WorkerOutcome::Exit { code: 0 }));
    assert_eq!(
        out.controls.len(),
        1,
        "only the worker's own record survives, got {:?}",
        out.controls
    );
    assert_eq!(out.controls[0].header_json, r#"{"kind":"envelope"}"#);
}

#[test]
fn set_idle_timeout_returns_previous_value() {
    let pool = start_pool(cfg(1, 100, 1024));
    // Initial value is 0 (disabled). First swap: previous=0, new=60.
    assert_eq!(pool.set_idle_timeout(60), 0);
    assert_eq!(pool.idle_timeout_secs(), 60);
    // Second swap returns the prior value we just set.
    assert_eq!(pool.set_idle_timeout(120), 60);
    assert_eq!(pool.idle_timeout_secs(), 120);
    // Disabling returns the prior value too.
    assert_eq!(pool.set_idle_timeout(0), 120);
    assert_eq!(pool.idle_timeout_secs(), 0);
}

#[test]
fn idle_timeout_zero_disables_recycle() {
    // With timeout=0 no amount of idleness recycles. Sweeping against an
    // instant an hour out states that far more strongly than sleeping
    // 100ms did, and costs nothing.
    let pool = start_pool(cfg(1, 100, 1024));
    let started = Instant::now();
    let pid_before = idle_pid(&pool);
    assert_eq!(pool.set_idle_timeout(0), 0);
    pool.sweep_idle_at(started + Duration::from_secs(3600));
    assert_eq!(idle_pid(&pool), pid_before, "no recycle when timeout=0");
}

#[test]
fn idle_timeout_recycles_idle_workers_only_past_the_threshold() {
    // 60-second idle timeout, swept against both sides of it.
    //
    // The under-threshold half is the half that discriminates: a sweep
    // that recycled everything unconditionally would pass a
    // past-threshold-only test. Reaching it by sleeping is not an
    // option — the wait would have to be shorter than the timeout, so
    // the timeout would have to be short, and a short timeout is
    // precisely what makes the other half racy.
    let pool = start_pool(cfg(1, 100, 1024));
    let started = Instant::now();
    let pid_before = idle_pid(&pool);
    pool.set_idle_timeout(60);

    pool.sweep_idle_at(started + Duration::from_secs(59));
    assert_eq!(
        idle_pid(&pool),
        pid_before,
        "a worker idle for less than the timeout must survive the sweep"
    );

    pool.sweep_idle_at(started + Duration::from_secs(61));
    assert_ne!(
        idle_pid(&pool),
        pid_before,
        "expected idle-recycle to replace the worker past the timeout"
    );
}

#[test]
fn idle_timeout_skips_busy_workers() {
    // While a worker is mid-call (Busy state), the sweep must skip
    // it — recycling a busy worker would yank the call's pipe and
    // surface as a transport error to the caller.
    let pool = start_pool_with_behavior(cfg(1, 100, 1024), Some("slow_secs=2"));
    let started = Instant::now();
    pool.set_idle_timeout(1);

    // Dispatch a 2s call on a background thread; it'll be Busy
    // mid-call when we sweep.
    let pool_clone = Arc::clone(&pool);
    let dispatch_handle = std::thread::spawn(move || {
        pool_clone
            .dispatch(b"x".to_vec(), CALL_HANG_GUARD_SECS, Vec::new())
            .expect("dispatch")
    });

    // Two separate conditions, so two separate mechanisms: wait for the
    // slot to actually flip to Busy, then sweep against an instant well
    // past the idle threshold. The old single 1200ms sleep stood in for
    // both and guaranteed neither.
    wait_until("the dispatched call to occupy the slot", || {
        any_slot_busy(&pool)
    });
    pool.sweep_idle_at(started + Duration::from_secs(60));

    // Slot should still be Busy (the call is in-flight). If the
    // sweep had recycled, the slot would be Idle with a fresh PID.
    let snap = pool.snapshot();
    assert!(
        snap.iter().any(|s| matches!(s, SlotSnapshot::Busy)),
        "busy worker must not be recycled mid-call, got snap={snap:?}"
    );

    // Let the call finish; verify it succeeded (no transport error).
    let out = dispatch_handle.join().expect("dispatch thread joined");
    assert!(matches!(out.outcome, WorkerOutcome::Exit { code: 0 }));
}

#[test]
fn user_code_fault_does_not_recycle() {
    // The fake runner returns Exit { code: 1 } on every call; the
    // pool must NOT recycle on user-code-level failure.
    let pool = start_pool_with_behavior(cfg(1, 100, 1024), Some("user_fault"));
    let pid_before = idle_pid(&pool);

    for _ in 0..20 {
        let out = dispatch(&pool, b"x");
        assert!(matches!(out.outcome, WorkerOutcome::Exit { code: 1 }));
    }
    assert_eq!(idle_pid(&pool), pid_before, "PID stable for user faults");
    assert_eq!(idle_call_count(&pool, pid_before), 20);
}

#[test]
fn recycle_on_call_count_exceeded() {
    let pool = start_pool(cfg(1, 3, 1024)); // recycle after 3 calls
    let first_pid = idle_pid(&pool);

    for _ in 0..3 {
        let out = dispatch(&pool, b"a");
        assert!(matches!(out.outcome, WorkerOutcome::Exit { code: 0 }));
    }
    // After 3 calls, the next call should be served by a fresh
    // worker because release saw call_count >= max.
    let second_pid = idle_pid(&pool);
    assert_ne!(second_pid, first_pid, "worker recycled after call cap");
}

#[test]
fn wrapper_crash_returns_error_and_recycles() {
    // crash_during_call_n=2: call 1 succeeds, call 2 crashes
    // (worker exits without writing response). After recycle, the
    // fresh worker also has crash_during_call_n=2 set (the env is
    // baked into the pool), so we only assert through to call 2's
    // crash. PID changes proves the recycle fired.
    let pool = start_pool_with_behavior(cfg(1, 100, 1024), Some("crash_during_call_n=2"));
    let first_pid = idle_pid(&pool);

    let out1 = pool
        .dispatch(b"first".to_vec(), CALL_HANG_GUARD_SECS, Vec::new())
        .expect("dispatch returns outcome");
    assert!(matches!(out1.outcome, WorkerOutcome::Exit { code: 0 }));

    let out2 = pool
        .dispatch(b"second".to_vec(), CALL_HANG_GUARD_SECS, Vec::new())
        .expect("dispatch returns outcome even on crash");
    assert!(
        matches!(out2.outcome, WorkerOutcome::Error { .. }),
        "out2 outcome = {:?}",
        out2.outcome
    );
    if let WorkerOutcome::Error { kind, .. } = out2.outcome {
        assert_eq!(kind, "wrapper_crash");
    }

    // Recycle should have replaced the worker.
    let second_pid = idle_pid(&pool);
    assert_ne!(second_pid, first_pid, "crashed worker replaced");
}

#[test]
fn pool_size_4_parallel_dispatches() {
    let pool = start_pool(cfg(4, 100, 1024));
    let pids_before: std::collections::HashSet<u32> = pool
        .snapshot()
        .into_iter()
        .filter_map(|s| match s {
            SlotSnapshot::Idle { pid, .. } => Some(pid),
            _ => None,
        })
        .collect();
    assert_eq!(pids_before.len(), 4);

    // Fire 12 dispatches across 12 threads.
    let pool_clone = Arc::clone(&pool);
    let mut handles = Vec::new();
    for i in 0..12 {
        let p = Arc::clone(&pool_clone);
        handles.push(std::thread::spawn(move || {
            let payload = format!("call-{i}");
            let out = p
                .dispatch(
                    payload.clone().into_bytes(),
                    CALL_HANG_GUARD_SECS,
                    Vec::new(),
                )
                .expect("ok");
            assert_eq!(out.stdout, payload.as_bytes());
            assert!(matches!(out.outcome, WorkerOutcome::Exit { code: 0 }));
        }));
    }
    for h in handles {
        h.join().expect("thread completes");
    }

    // All 4 workers should still be the same PIDs — call_count below
    // recycle threshold.
    let pids_after: std::collections::HashSet<u32> = pool
        .snapshot()
        .into_iter()
        .filter_map(|s| match s {
            SlotSnapshot::Idle { pid, .. } => Some(pid),
            _ => None,
        })
        .collect();
    assert_eq!(pids_after, pids_before);
}

#[test]
fn fifo_queue_serializes_callers() {
    // pool_size=1, max_queue_depth=4 + 5 concurrent dispatches:
    // 1 in-flight, up to 4 queued, total 5 fits exactly. All
    // complete; the queue serializes them.
    let mut wpc = cfg(1, 100, 1024);
    wpc.max_queue_depth = Some(4);
    let pool = start_pool(wpc);
    let pool_clone = Arc::clone(&pool);
    let mut handles = Vec::new();
    for i in 0..5u8 {
        let p = Arc::clone(&pool_clone);
        handles.push(std::thread::spawn(move || {
            p.dispatch(vec![i], CALL_HANG_GUARD_SECS, Vec::new())
                .expect("dispatch")
        }));
    }
    let outs: Vec<DispatchOutcome> = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .collect();
    assert_eq!(outs.len(), 5);
    for out in &outs {
        assert!(matches!(out.outcome, WorkerOutcome::Exit { code: 0 }));
    }
    // Serialization is the claim, so assert serialization: one slot,
    // and every one of the five calls went through it. The previous
    // `start.elapsed() < 10s` asserted nothing about ordering — it was
    // a wall-clock budget, and the only thing it ever caught was a
    // loaded CI host.
    let pid = idle_pid(&pool);
    assert_eq!(
        idle_call_count(&pool, pid),
        5,
        "all five callers must have queued through the single worker"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn recycle_on_rss_exceeded() {
    // Linux-only: relies on /proc/<pid>/statm. The fake runner
    // allocates 50 MiB per call; max_rss_mb=10 forces recycle on
    // call 1. The replacement also has leak_50mib_per_call (env
    // baked into pool), but call 1 alone is enough to verify the
    // recycle fired.
    let pool = start_pool_with_behavior(cfg(1, 100, 10), Some("leak_50mib_per_call"));
    let first_pid = idle_pid(&pool);

    let _ = dispatch(&pool, b"call-1");
    // After call 1, RSS should be over 10 MiB → worker recycled.
    let second_pid = idle_pid(&pool);
    assert_ne!(
        second_pid, first_pid,
        "worker recycled after RSS exceeded cap"
    );
}

#[test]
fn queue_full_returns_error() {
    // pool_size=1, max_queue_depth=1. With one in-flight slow caller
    // and one queued, the third caller must be rejected with QueueFull.
    let mut wpc = cfg(1, 100, 1024);
    wpc.max_queue_depth = Some(1);
    let pool = start_pool_with_behavior(wpc, Some("slow_secs=2"));

    let p1 = Arc::clone(&pool);
    let p2 = Arc::clone(&pool);
    let h1 =
        std::thread::spawn(move || p1.dispatch(b"a".to_vec(), CALL_HANG_GUARD_SECS, Vec::new()));
    // The first caller must hold the only slot before the second can
    // queue behind it; the second must be parked in the queue before a
    // third can overflow it. Both are observable, so neither is timed.
    wait_until("the first caller to occupy the only slot", || {
        any_slot_busy(&pool)
    });
    let h2 =
        std::thread::spawn(move || p2.dispatch(b"b".to_vec(), CALL_HANG_GUARD_SECS, Vec::new()));
    wait_until("the second caller to park in the queue", || {
        pool.queued_waiters() == 1
    });

    // Third should hit QueueFull.
    let res = pool.dispatch(b"c".to_vec(), CALL_HANG_GUARD_SECS, Vec::new());
    assert!(
        res.is_err(),
        "third dispatch must hit queue cap, got {:?}",
        res
    );

    let _ = h1.join().expect("h1");
    let _ = h2.join().expect("h2");
}

// ─── readiness gate integration tests ────────────────────────────────────────
//
// These tests build a real `WorkerPool` (against the fake-runner
// fixture) but stand up a tempdir-scoped after_start.sh script
// instead of the production `/etc/mvm/hooks/after_start.sh`. The pool
// API takes the script path through `ReadinessConfig`, so we can
// point at the fixture without touching `/etc`.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn write_probe(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    let mut f = fs::File::create(&p).expect("create probe");
    f.write_all(body.as_bytes()).expect("write probe body");
    let mut perms = fs::metadata(&p).expect("probe metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&p, perms).expect("chmod probe");
    p
}

/// Build a pool but don't `mark_ready`. The dispatch path returns
/// `NotReady` until `wait_for_ready` succeeds.
fn start_pool_unready(cfg: WarmProcessConfig) -> Arc<WorkerPool> {
    let entry = Arc::new(validated_for_fake_runner());
    WorkerPool::start(cfg, entry, Vec::new()).expect("pool start")
}

#[test]
fn dispatch_refuses_until_readiness_marked() {
    let pool = start_pool_unready(cfg(1, 100, 1024));
    let res = pool.dispatch(b"hello".to_vec(), CALL_HANG_GUARD_SECS, Vec::new());
    assert!(matches!(res, Err(DispatchError::NotReady)));
    assert!(!pool.is_ready());
    pool.mark_ready();
    assert!(pool.is_ready());
    let out = pool
        .dispatch(b"hello".to_vec(), CALL_HANG_GUARD_SECS, Vec::new())
        .expect("post-ready dispatch ok");
    assert_eq!(out.stdout, b"hello");
}

#[test]
fn wait_for_ready_succeeds_against_passing_probe() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let probe = write_probe(tmp.path(), "after_start.sh", "#!/bin/sh\nexit 0\n");
    let pool = start_pool_unready(cfg(1, 100, 1024));
    // Generous bound: this test asserts the probe *succeeds*, so the
    // timeout is only here to stop a hang. Sizing it tightly turns a
    // busy host into a red test without telling anyone anything.
    let cfg_probe = ReadinessConfig::new(probe)
        .with_timeout(Duration::from_secs(60))
        .with_interval(Duration::from_millis(50));
    pool.wait_for_ready(&cfg_probe).expect("ready");
    assert!(pool.is_ready());
    pool.dispatch(b"ok".to_vec(), CALL_HANG_GUARD_SECS, Vec::new())
        .expect("dispatch ok after ready");
}

#[test]
fn wait_for_ready_succeeds_after_initial_failures() {
    // Probe fails twice then exits 0 — after_start.sh exits 1 thrice
    // then 0.
    let tmp = tempfile::tempdir().expect("tempdir");
    let counter = tmp.path().join("count");
    fs::write(&counter, "0").expect("seed counter");
    let body = format!(
        "#!/bin/sh\nc=$(cat {ctr})\nc=$((c+1))\necho $c > {ctr}\n[ $c -ge 3 ] && exit 0\nexit 1\n",
        ctr = counter.display()
    );
    let probe = write_probe(tmp.path(), "after_start.sh", &body);
    let pool = start_pool_unready(cfg(1, 100, 1024));
    // Generous for the same reason as the passing-probe test: three
    // probe attempts at a 50ms interval, so the subject is the retry,
    // not the deadline.
    let cfg_probe = ReadinessConfig::new(probe)
        .with_timeout(Duration::from_secs(60))
        .with_interval(Duration::from_millis(50));

    // While warming, dispatch should fail-closed.
    assert!(matches!(
        pool.dispatch(b"early".to_vec(), CALL_HANG_GUARD_SECS, Vec::new()),
        Err(DispatchError::NotReady)
    ));

    pool.wait_for_ready(&cfg_probe).expect("warmed up");
    assert!(pool.is_ready());
    let out = pool
        .dispatch(b"after-warmup".to_vec(), CALL_HANG_GUARD_SECS, Vec::new())
        .expect("dispatch after warmup");
    assert_eq!(out.stdout, b"after-warmup");
}

#[test]
fn wait_for_ready_marks_ready_when_probe_missing() {
    // Defensive: if for any reason the baked after_start.sh isn't
    // there, the pool should fall through cleanly and accept invokes
    // (an absent script is semantically equivalent to "no after_start
    // hook declared").
    let pool = start_pool_unready(cfg(1, 100, 1024));
    let cfg_probe = ReadinessConfig::new(PathBuf::from("/nonexistent/after_start.sh"))
        .with_timeout(Duration::from_millis(200))
        .with_interval(Duration::from_millis(50));
    pool.wait_for_ready(&cfg_probe)
        .expect("missing probe is ok");
    assert!(pool.is_ready());
    pool.dispatch(b"ok".to_vec(), CALL_HANG_GUARD_SECS, Vec::new())
        .expect("dispatch ok with absent probe");
}

#[test]
fn wait_for_ready_timeout_leaves_pool_not_ready() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let probe = write_probe(tmp.path(), "after_start.sh", "#!/bin/sh\nexit 1\n");
    let pool = start_pool_unready(cfg(1, 100, 1024));
    let cfg_probe = ReadinessConfig::new(probe)
        .with_timeout(Duration::from_millis(250))
        .with_interval(Duration::from_millis(50));
    let err = pool.wait_for_ready(&cfg_probe).unwrap_err();
    assert!(
        matches!(
            err,
            mvm_agentd::lifecycle_hooks::ReadinessError::Timeout { .. }
        ),
        "expected Timeout, got {err:?}"
    );
    assert!(!pool.is_ready(), "timeout must leave pool NotReady");
    assert!(matches!(
        pool.dispatch(b"x".to_vec(), CALL_HANG_GUARD_SECS, Vec::new()),
        Err(DispatchError::NotReady)
    ));
}
