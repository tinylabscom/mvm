//! Warm-process worker pool.
//!
//! When `/etc/mvm/runtime.json` carries `concurrency.kind =
//! "warm_process"`, the agent stands up a fixed-size pool of
//! long-running wrapper processes at boot. Each `mvmctl invoke`
//! is dispatched to a free worker over its stdin/stdout pipes via
//! length-prefixed JSON frames (see [`crate::worker_protocol`]).
//!
//! Compared to the cold path:
//! - The wrapper's interpreter cold-start happens once per worker,
//!   not once per invoke. Per-call latency drops by hundreds of ms
//!   (Python especially).
//! - The single-call-per-VM invariant is bypassed: up to `pool_size`
//!   calls can be in flight in the same VM. Backpressure is a FIFO
//!   queue, capped at `max_queue_depth` (default `2 * pool_size`).
//! - Workers are recycled on call-count, RSS, or wrapper crash.
//! - Cross-call wrapper state is the user's responsibility; the agent
//!   does not scrub state between calls.
//!
//! The host wire (vsock `RunEntrypoint` → `EntrypointEvent` stream)
//! is bit-identical to the cold path. The agent synthesizes the
//! existing event stream from the worker's single buffered response
//! frame.

use std::io::{self, BufReader};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::entrypoint::{self, ControlRecord, ValidatedEntrypoint};
use crate::lifecycle_hooks::{self, ReadinessConfig, ReadinessError};
use crate::runtime_config::WarmProcessConfig;
use crate::worker_protocol::{
    WorkerCallRequest, WorkerCallResponse, WorkerOutcome, read_pipe_frame, write_pipe_frame,
};

/// Grace period between SIGTERM and SIGKILL when recycling or
/// shutting a worker. Mirrors the cold-path
/// `CallCaps::v1().kill_grace_period`.
pub const DEFAULT_KILL_GRACE: Duration = Duration::from_secs(2);

/// One worker process plus the per-worker bookkeeping the dispatcher
/// needs between calls.
pub(crate) struct WorkerHandle {
    pid: u32,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// stderr drains in the background to avoid blocking the worker
    /// when its stderr pipe fills up. We don't surface the bytes —
    /// they go straight to the agent's own stderr (inherited as
    /// "mvm-guest-agent: worker N: …"). Held so Drop joins the thread.
    _stderr_drain: thread::JoinHandle<()>,
    call_count: u64,
    last_rss_bytes: u64,
    /// Wall-clock time of the most recent successful response. Set on
    /// spawn so a fresh worker isn't immediately considered idle, then
    /// updated by `release()` after every call. Read by the
    /// `idle-recycler` thread to find workers idle past the
    /// substrate-side timeout (UpdateIdleTimeout vsock verb).
    last_used_at: Instant,
}

impl Drop for WorkerHandle {
    fn drop(&mut self) {
        // Best-effort cleanup. The watchdog and recycle paths
        // typically race ahead of Drop; this is the catch-all when
        // the pool itself is being torn down or the handle is
        // dropped due to a panic.
        entrypoint::kill_and_reap(&mut self.child, DEFAULT_KILL_GRACE);
    }
}

/// One slot in the pool. Slots are indexed by position; the index is
/// stable across replacements so debug logs can refer to "worker 3".
enum WorkerSlot {
    Idle(WorkerHandle),
    Busy,
    /// Slot's worker died and respawn has not yet succeeded. The
    /// recovery thread retries periodically.
    Dead,
}

struct PoolState {
    slots: Vec<WorkerSlot>,
    pending_waiters: usize,
}

/// Errors returned by [`WorkerPool::dispatch`] before the call ever
/// reaches a worker. Successful runs return [`DispatchOutcome`] even
/// for user-code failures.
#[derive(Debug)]
pub enum DispatchError {
    /// All workers busy and the queue is at `max_queue_depth`.
    /// Maps to `EntrypointEvent::Error { kind: Busy }` host-side.
    QueueFull,
    /// Pool is shutting down. New calls refuse fast-fail.
    ShuttingDown,
    /// Every slot is `Dead` and respawn is failing. Surfaces as
    /// `EntrypointEvent::Error { kind: InternalError }`.
    NoLiveWorkers,
    /// Pool processes have spawned but the `after_start.sh` readiness
    /// probe has not yet succeeded — the workload says it's still
    /// warming up. Maps to
    /// `EntrypointEvent::Error { kind: Busy }` host-side with a
    /// distinguishing message; admission can surface this as
    /// "warming up" rather than overload.
    NotReady,
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::QueueFull => write!(f, "worker pool queue full"),
            DispatchError::ShuttingDown => write!(f, "worker pool is shutting down"),
            DispatchError::NoLiveWorkers => write!(f, "worker pool has no live workers"),
            DispatchError::NotReady => {
                write!(
                    f,
                    "worker pool warming up — after_start probe not yet ready"
                )
            }
        }
    }
}

impl std::error::Error for DispatchError {}

/// Result of a single dispatched call. The agent maps this onto
/// the host-facing `EntrypointEvent` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Per-call control-channel records the wrapper emitted via the
    /// structured-envelope path. The agent forwards each as one
    /// `EntrypointEvent::Control` frame.
    pub controls: Vec<ControlRecord>,
    pub outcome: WorkerOutcome,
}

impl DispatchOutcome {
    /// Synthesize a transport-error response — used when the worker
    /// crashes mid-call or fails to produce a frame.
    fn transport_error(kind: &str, message: String) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            controls: Vec::new(),
            outcome: WorkerOutcome::Error {
                kind: kind.to_string(),
                message,
            },
        }
    }
}

/// Pool of long-running wrapper workers.
pub struct WorkerPool {
    state: Mutex<PoolState>,
    cv: Condvar,
    cfg: WarmProcessConfig,
    entrypoint: Arc<ValidatedEntrypoint>,
    /// Env vars forwarded into each spawned worker. The pool always
    /// `env_clear()`s before applying these — production wrappers
    /// should not rely on host-inherited env. The list is populated
    /// by the agent at boot from a curated set (e.g., `PATH`,
    /// `LANG`); tests use it to drive test-fixture behavior.
    worker_env: Vec<(String, String)>,
    shutdown: AtomicBool,
    /// Substrate-side idle-recycle timeout in seconds. `0` disables
    /// idle-based recycling — only `max_calls_per_worker` and
    /// `max_rss_mb` triggers remain. Updated at runtime via
    /// `set_idle_timeout` (driven by the `UpdateIdleTimeout` vsock
    /// verb). The recycler-sweep thread reads this value each tick.
    idle_timeout_secs: AtomicU64,
    /// Flips to `true` after
    /// the workload's `after_start.sh` readiness probe exits 0 (or
    /// the script is absent / the workload declares no after_start
    /// hook). Until then, `dispatch` refuses with
    /// [`DispatchError::NotReady`] so we don't ship invokes to a
    /// process that hasn't said it's warm yet.
    ///
    /// Initialized `false` in `start()`. The agent calls
    /// [`WorkerPool::wait_for_ready`] (blocking) or
    /// [`WorkerPool::mark_ready`] (no probe declared) before opening
    /// the accept loop's traffic spigot.
    ready: AtomicBool,
}

impl WorkerPool {
    /// Boot the pool: spawn `cfg.pool_size` workers, each from the
    /// validated wrapper FD. Fails fast on the first spawn error —
    /// caller (the agent main) should exit non-zero so misconfigured
    /// images don't appear to start successfully.
    ///
    /// `worker_env` is the set of env vars set on each worker at
    /// spawn time. The pool's spawn path always calls
    /// `Command::env_clear()` first, then applies these — workers
    /// cannot inherit anything else.
    pub fn start(
        cfg: WarmProcessConfig,
        entrypoint: Arc<ValidatedEntrypoint>,
        worker_env: Vec<(String, String)>,
    ) -> io::Result<Arc<Self>> {
        // Set RLIMIT_CORE=0 on the agent so all child workers
        // inherit it. Mirrors the cold-path one-shot in
        // `entrypoint::execute`.
        entrypoint::set_no_core_dumps();

        let mut slots = Vec::with_capacity(cfg.pool_size);
        for i in 0..cfg.pool_size {
            let handle = spawn_worker(&entrypoint, &worker_env)
                .map_err(|e| io::Error::other(format!("spawn worker {i}: {e}")))?;
            eprintln!(
                "mvm-guest-agent: warm-process worker {i} spawned pid={}",
                handle.pid
            );
            slots.push(WorkerSlot::Idle(handle));
        }

        eprintln!(
            "mvm-guest-agent: warm-process pool active (pool_size={}, max_calls_per_worker={}, \
             max_rss_mb={}, queue_depth={}); cross-call wrapper state is the user's responsibility \
             — the agent does not scrub between calls (ADR-0011 §state)",
            cfg.pool_size,
            cfg.max_calls_per_worker,
            cfg.max_rss_mb,
            cfg.effective_queue_depth(),
        );

        let pool = Arc::new(Self {
            state: Mutex::new(PoolState {
                slots,
                pending_waiters: 0,
            }),
            cv: Condvar::new(),
            cfg,
            entrypoint,
            worker_env,
            shutdown: AtomicBool::new(false),
            // Off by default. `mvmctl session set-timeout` →
            // `UpdateIdleTimeout` vsock verb sets this at runtime;
            // host-side reaper remains the safety net regardless.
            idle_timeout_secs: AtomicU64::new(0),
            // Workers are spawned but not yet
            // dispatchable until the after_start probe says they are
            // (or the caller calls `mark_ready` directly because no
            // probe was declared). `dispatch` returns `NotReady` while
            // this is `false`.
            ready: AtomicBool::new(false),
        });

        // Spawn the idle-recycler sweep thread. It reads
        // `idle_timeout_secs` on every tick — when 0, the loop just
        // sleeps. Holding a `Weak` reference instead of an `Arc`
        // means the thread doesn't keep the pool alive past
        // `shutdown()`.
        spawn_idle_recycler(Arc::downgrade(&pool));

        Ok(pool)
    }

    /// Update the idle-recycle timeout. Returns the previous value
    /// so the caller (the agent's `UpdateIdleTimeout` handler) can
    /// surface the delta in its ACK frame.
    ///
    /// `secs == 0` disables idle-based recycling — workers stay
    /// resident until `max_calls_per_worker` / `max_rss_mb` triggers
    /// or shutdown.
    pub fn set_idle_timeout(&self, secs: u64) -> u64 {
        self.idle_timeout_secs.swap(secs, Ordering::Release)
    }

    /// Read the current idle-recycle timeout (atomic snapshot).
    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs.load(Ordering::Acquire)
    }

    /// Snapshot whether the pool is currently dispatchable. `false`
    /// until `wait_for_ready` / `mark_ready` flips it; once set,
    /// stays `true` until the pool is dropped.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Mark the pool dispatchable without running a readiness probe.
    /// Used by the agent when the workload declared no `after_start`
    /// hook (the baked script is missing), and by tests that don't
    /// want to script a probe binary.
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// Block until the after_start readiness probe at
    /// `cfg.script_path` succeeds, then mark the pool dispatchable.
    /// On a missing script (no `after_start` hook declared) the pool
    /// is marked ready immediately and `Ok(())` returned — the
    /// factory always bakes the script, but defensive handling keeps
    /// us robust if rootfs assembly is interrupted.
    ///
    /// Called by the agent's `init_warm_pool`
    /// after [`WorkerPool::start`] returns, before the accept loop
    /// begins handling traffic. On timeout / exec error, the pool
    /// stays `NotReady` and subsequent `dispatch` calls refuse fast;
    /// the caller can log + leave the agent up so an operator sees
    /// the failure mode (admission gate, host log).
    pub fn wait_for_ready(&self, cfg: &ReadinessConfig) -> Result<(), ReadinessError> {
        match lifecycle_hooks::poll_readiness(cfg) {
            Ok(()) => {
                self.ready.store(true, Ordering::Release);
                Ok(())
            }
            Err(ReadinessError::ScriptMissing { script }) => {
                // No after_start hook declared (factory should always
                // bake the script, but if it's gone, fall through
                // cleanly — empty-hook == ready).
                eprintln!(
                    "mvm-guest-agent: after_start probe `{}` not present; marking pool ready",
                    script.display()
                );
                self.ready.store(true, Ordering::Release);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Dispatch one call to a free worker. Blocks (FIFO via Condvar)
    /// if all workers are busy, up to `max_queue_depth` total
    /// waiters; the `(pool_size + 1)`th waiter gets `QueueFull`.
    ///
    /// `timeout_secs` is forwarded to the worker (informational) and
    /// enforced by an agent-side watchdog that SIGKILLs the worker's
    /// process group on expiry. The worker can be killed mid-call;
    /// the read-frame returns `UnexpectedEof` and we surface
    /// `Outcome::Error { kind: "wrapper_crash" }`.
    pub fn dispatch(
        self: &Arc<Self>,
        stdin: Vec<u8>,
        timeout_secs: u64,
        env: Vec<(String, String)>,
    ) -> Result<DispatchOutcome, DispatchError> {
        // Refuse dispatch until the after_start probe has succeeded.
        // Cheap atomic load on the hot path.
        if !self.ready.load(Ordering::Acquire) {
            return Err(DispatchError::NotReady);
        }
        let (idx, mut handle) = self.acquire()?;
        let pgid = handle.pid as i32;

        // Watchdog: SIGKILLs the worker group at deadline. Cancelled
        // on response by setting the atomic. Joined regardless.
        let cancelled = Arc::new(AtomicBool::new(false));
        let watchdog = spawn_watchdog(pgid, timeout_secs, Arc::clone(&cancelled));

        let result = run_one_call(&mut handle, stdin, timeout_secs, env);
        cancelled.store(true, Ordering::Release);
        let _ = watchdog.join();

        let recycle = self.should_recycle(&mut handle, &result);
        self.release(idx, handle, recycle);

        Ok(match result {
            Ok(resp) => DispatchOutcome {
                stdout: resp.stdout,
                stderr: resp.stderr,
                // Forward the worker-emitted control records through to
                // the agent as `ControlRecord`s. The shape
                // matches `entrypoint::ControlRecord` modulo base64
                // encoding on the warm-worker JSON wire.
                controls: resp
                    .controls
                    .into_iter()
                    .map(|r| ControlRecord {
                        header_json: r.header_json,
                        payload: r.payload,
                    })
                    .collect(),
                outcome: resp.outcome,
            },
            Err(WorkerCallError::Crash(message)) => {
                DispatchOutcome::transport_error("wrapper_crash", message)
            }
            Err(WorkerCallError::Protocol(message)) => {
                DispatchOutcome::transport_error("wrapper_crash", message)
            }
        })
    }

    /// Initiate shutdown. New `dispatch` calls return
    /// `ShuttingDown`. Idle workers are SIGTERM/SIGKILL'd via Drop.
    /// Busy workers run to completion (Drop fires on release). The
    /// caller may sleep `grace` to let in-flight calls drain.
    pub fn shutdown(&self, grace: Duration) {
        self.shutdown.store(true, Ordering::Release);
        self.cv.notify_all();
        // Drain idle workers right away. Busy workers tear down
        // on release.
        let mut st = self.state.lock().expect("worker pool state mutex poisoned");
        for slot in st.slots.iter_mut() {
            if let WorkerSlot::Idle(_) = slot {
                // Replace with Dead — Drop on the moved handle kills
                // the worker.
                *slot = WorkerSlot::Dead;
            }
        }
        drop(st);
        // Give callers a chance to observe in-flight completions.
        thread::sleep(grace.min(Duration::from_secs(30)));
    }

    /// Snapshot of slot states for observability / tests.
    pub fn snapshot(&self) -> Vec<SlotSnapshot> {
        let st = self.state.lock().expect("worker pool state mutex poisoned");
        st.slots
            .iter()
            .map(|slot| match slot {
                WorkerSlot::Idle(h) => SlotSnapshot::Idle {
                    pid: h.pid,
                    call_count: h.call_count,
                    last_rss_bytes: h.last_rss_bytes,
                },
                WorkerSlot::Busy => SlotSnapshot::Busy,
                WorkerSlot::Dead => SlotSnapshot::Dead,
            })
            .collect()
    }

    fn acquire(self: &Arc<Self>) -> Result<(usize, WorkerHandle), DispatchError> {
        let mut st = self.state.lock().expect("worker pool state mutex poisoned");
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return Err(DispatchError::ShuttingDown);
            }
            if let Some(idx) = st
                .slots
                .iter()
                .position(|s| matches!(s, WorkerSlot::Idle(_)))
            {
                let slot = std::mem::replace(&mut st.slots[idx], WorkerSlot::Busy);
                let WorkerSlot::Idle(handle) = slot else {
                    unreachable!("position() guarantees Idle");
                };
                return Ok((idx, handle));
            }
            // No idle. If every slot is Dead, fail fast — there's no
            // hope of waking up unless a recovery thread succeeds,
            // which we don't model in v0.2.
            if st.slots.iter().all(|s| matches!(s, WorkerSlot::Dead)) {
                return Err(DispatchError::NoLiveWorkers);
            }
            // Some are Busy; wait for one to be released.
            if st.pending_waiters >= self.cfg.effective_queue_depth() {
                return Err(DispatchError::QueueFull);
            }
            st.pending_waiters += 1;
            st = self.cv.wait(st).expect("worker pool condvar wait poisoned");
            st.pending_waiters -= 1;
        }
    }

    fn release(self: &Arc<Self>, idx: usize, mut handle: WorkerHandle, recycle: bool) {
        // Bump idle clock — we just finished a call, so this worker
        // is fresh. The recycler reads `last_used_at` to decide
        // whether the worker has been idle past the timeout.
        handle.last_used_at = Instant::now();
        let mut st = self.state.lock().expect("worker pool state mutex poisoned");
        if recycle {
            // Drop the handle inside this scope so the old worker is
            // killed before we attempt to spawn a replacement (their
            // resource caps may overlap during overshoot).
            drop(handle);
            match spawn_worker(&self.entrypoint, &self.worker_env) {
                Ok(new_handle) => {
                    eprintln!(
                        "mvm-guest-agent: warm-process worker {idx} replaced pid={}",
                        new_handle.pid
                    );
                    st.slots[idx] = WorkerSlot::Idle(new_handle);
                }
                Err(e) => {
                    eprintln!(
                        "mvm-guest-agent: warm-process worker {idx} respawn failed: {e}; \
                         marking slot dead"
                    );
                    st.slots[idx] = WorkerSlot::Dead;
                }
            }
        } else {
            st.slots[idx] = WorkerSlot::Idle(handle);
        }
        self.cv.notify_one();
    }

    fn should_recycle(
        self: &Arc<Self>,
        handle: &mut WorkerHandle,
        result: &Result<WorkerCallResponse, WorkerCallError>,
    ) -> bool {
        // Wrapper-level transport failure → always recycle.
        if result.is_err() {
            return true;
        }
        // User code may legitimately exit non-zero on its own
        // (e.g. a Python wrapper translates an unhandled exception
        // to a sanitized envelope and exit 1). Don't recycle on that
        // — only on wrapper-side failures.
        handle.call_count = handle.call_count.saturating_add(1);
        if handle.call_count >= self.cfg.max_calls_per_worker {
            eprintln!(
                "mvm-guest-agent: warm-process worker pid={} recycle (call_count {} >= {})",
                handle.pid, handle.call_count, self.cfg.max_calls_per_worker
            );
            return true;
        }
        if let Some(rss) = sample_rss_bytes(handle.pid) {
            handle.last_rss_bytes = rss;
            let cap = self.cfg.max_rss_mb.saturating_mul(1024 * 1024);
            if rss > cap {
                eprintln!(
                    "mvm-guest-agent: warm-process worker pid={} recycle (rss {} > {})",
                    handle.pid, rss, cap
                );
                return true;
            }
        }
        false
    }
}

/// Public projection of slot state (for tests and observability).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotSnapshot {
    Idle {
        pid: u32,
        call_count: u64,
        last_rss_bytes: u64,
    },
    Busy,
    Dead,
}

#[derive(Debug)]
enum WorkerCallError {
    /// The worker died (EOF / non-zero exit / killed by watchdog).
    Crash(String),
    /// The worker stayed up but produced an unparseable frame —
    /// equally fatal to the call, equally a recycle trigger.
    Protocol(String),
}

impl std::fmt::Display for WorkerCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerCallError::Crash(s) => write!(f, "worker crash: {s}"),
            WorkerCallError::Protocol(s) => write!(f, "worker protocol error: {s}"),
        }
    }
}

fn run_one_call(
    handle: &mut WorkerHandle,
    stdin: Vec<u8>,
    timeout_secs: u64,
    env: Vec<(String, String)>,
) -> Result<WorkerCallResponse, WorkerCallError> {
    let req = WorkerCallRequest {
        stdin,
        timeout_secs,
        env,
    };
    write_pipe_frame(&mut handle.stdin, &req)
        .map_err(|e| WorkerCallError::Crash(format!("write request frame: {e}")))?;
    read_pipe_frame::<_, WorkerCallResponse>(&mut handle.stdout).map_err(|e| match e.kind() {
        io::ErrorKind::UnexpectedEof => WorkerCallError::Crash(format!("EOF on stdout: {e}")),
        io::ErrorKind::InvalidData => WorkerCallError::Protocol(e.to_string()),
        _ => WorkerCallError::Protocol(e.to_string()),
    })
}

fn spawn_worker(
    entrypoint: &Arc<ValidatedEntrypoint>,
    worker_env: &[(String, String)],
) -> io::Result<WorkerHandle> {
    let program = entrypoint::spawn_path(entrypoint);

    // Same envelope as `entrypoint::execute` minus the per-call
    // tmpdir (workers are shared across calls so a per-worker tmpdir
    // would leak per-call state — the wrapper takes responsibility
    // for per-call hygiene). env_clear first, then
    // apply the curated `worker_env` set, then own pgrp, RLIMIT_CORE
    // inheritance from set_no_core_dumps in start().
    let mut cmd = Command::new(&program);
    cmd.env_clear();
    for (k, v) in worker_env {
        cmd.env(k, v);
    }
    cmd.process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let pid = child.id();
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("stdin pipe missing"))?;
    let stdout = BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("stdout pipe missing"))?,
    );
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("stderr pipe missing"))?;

    let stderr_drain = thread::spawn(move || {
        // Mirror worker stderr to the agent's stderr line by line so
        // ops can see panics / sanitized envelopes. Bounded by the
        // pipe buffer; we don't accumulate.
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            eprintln!("mvm-guest-agent: worker pid={pid}: {line}");
        }
    });

    Ok(WorkerHandle {
        pid,
        child,
        stdin,
        stdout,
        _stderr_drain: stderr_drain,
        call_count: 0,
        last_rss_bytes: 0,
        last_used_at: Instant::now(),
    })
}

/// Idle-recycler sweep thread. Reaps `Idle` workers whose
/// `last_used_at` is older than the pool's current
/// `idle_timeout_secs`. Sleeps a fixed quantum between sweeps —
/// fine-grained idle detection isn't necessary; the host reaper
/// catches anything missed within its own polling window.
///
/// Holds a `Weak<WorkerPool>` so the pool can be dropped without
/// the thread keeping it alive. The thread exits on the first
/// `Weak::upgrade` failure (pool gone) or when `shutdown` is set.
fn spawn_idle_recycler(weak_pool: std::sync::Weak<WorkerPool>) -> thread::JoinHandle<()> {
    /// How often the recycler sweeps. Picked smaller than the host
    /// reaper's polling cadence so a workload-bound agent isn't
    /// hostage to host activity for fine-grained reaping. 10 s is
    /// a reasonable budget for a pool that recycles a worker
    /// every few minutes — picking the same number as the
    /// docker/podman default health-check interval, also chosen
    /// for predictability.
    const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

    thread::spawn(move || {
        loop {
            thread::sleep(SWEEP_INTERVAL);
            let Some(pool) = weak_pool.upgrade() else {
                return;
            };
            if pool.shutdown.load(Ordering::Acquire) {
                return;
            }
            pool.sweep_idle();
        }
    })
}

impl WorkerPool {
    /// Single sweep: walk the slots, find `Idle` workers whose
    /// `last_used_at` is older than the current `idle_timeout_secs`,
    /// and recycle each in place. Holds the state lock for the
    /// duration of the sweep — short, since we only `Instant::now`
    /// + compare per slot.
    ///
    /// Public so integration tests can drive the sweep
    /// deterministically without waiting for the recycler thread's
    /// tick. Production callers should let the background recycler
    /// run on its own cadence.
    pub fn sweep_idle(self: &Arc<Self>) {
        let secs = self.idle_timeout_secs.load(Ordering::Acquire);
        if secs == 0 {
            return;
        }
        let max_idle = Duration::from_secs(secs);
        let now = Instant::now();

        let mut to_recycle: Vec<usize> = Vec::new();
        {
            let st = self.state.lock().expect("worker pool state mutex poisoned");
            for (idx, slot) in st.slots.iter().enumerate() {
                if let WorkerSlot::Idle(h) = slot
                    && now.duration_since(h.last_used_at) >= max_idle
                {
                    to_recycle.push(idx);
                }
            }
        }
        for idx in to_recycle {
            self.recycle_idle_slot(idx);
        }
    }

    /// Replace the worker at `idx` with a fresh one. Skips the slot
    /// if it's no longer `Idle` (raced with `acquire`). Best-effort
    /// — if respawn fails, the slot is marked `Dead` and the
    /// existing `release()`-path retry policy applies.
    fn recycle_idle_slot(self: &Arc<Self>, idx: usize) {
        let mut st = self.state.lock().expect("worker pool state mutex poisoned");
        let slot = std::mem::replace(&mut st.slots[idx], WorkerSlot::Busy);
        let WorkerSlot::Idle(handle) = slot else {
            // Race: slot became Busy or Dead between sweep and
            // recycle. Put it back and skip.
            st.slots[idx] = slot;
            return;
        };
        let pid = handle.pid;
        // Drop the old handle inside the lock so its `Drop` runs
        // (kill_and_reap) before we re-spawn — keeps OS-level fd /
        // PID pressure consistent.
        drop(handle);
        eprintln!("mvm-guest-agent: warm-process worker {idx} idle-recycle pid={pid}");
        match spawn_worker(&self.entrypoint, &self.worker_env) {
            Ok(new_handle) => {
                eprintln!(
                    "mvm-guest-agent: warm-process worker {idx} replaced pid={}",
                    new_handle.pid
                );
                st.slots[idx] = WorkerSlot::Idle(new_handle);
            }
            Err(e) => {
                eprintln!(
                    "mvm-guest-agent: warm-process worker {idx} idle-recycle respawn failed: {e}; \
                     marking slot dead"
                );
                st.slots[idx] = WorkerSlot::Dead;
            }
        }
        self.cv.notify_one();
    }
}

fn spawn_watchdog(
    pgid: i32,
    timeout_secs: u64,
    cancelled: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        // Poll with a short interval so cancellation is fast.
        while Instant::now() < deadline {
            if cancelled.load(Ordering::Acquire) {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        if cancelled.load(Ordering::Acquire) {
            return;
        }
        // SAFETY: kill is async-signal-safe.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    })
}

/// Read RSS in bytes from `/proc/<pid>/statm`. Field 1 (0-indexed)
/// is `resident` in pages. Returns `None` if the file can't be read
/// or parsed — the caller treats absent samples as "no recycle
/// triggered by RSS" rather than failing the call.
fn sample_rss_bytes(pid: u32) -> Option<u64> {
    let path = format!("/proc/{pid}/statm");
    let raw = std::fs::read_to_string(path).ok()?;
    let pages: u64 = raw.split_whitespace().nth(1)?.parse().ok()?;
    let pagesize = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pagesize <= 0 {
        return None;
    }
    Some(pages.saturating_mul(pagesize as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_config::InProcessMode;

    #[test]
    fn dispatch_error_display_strings() {
        assert!(format!("{}", DispatchError::QueueFull).contains("queue full"));
        assert!(format!("{}", DispatchError::ShuttingDown).contains("shutting down"));
        assert!(format!("{}", DispatchError::NoLiveWorkers).contains("no live workers"));
        assert!(format!("{}", DispatchError::NotReady).contains("warming up"));
    }

    #[test]
    fn transport_error_constructor_shape() {
        let o = DispatchOutcome::transport_error("wrapper_crash", "EOF".into());
        assert_eq!(o.stdout, Vec::<u8>::new());
        assert!(matches!(o.outcome, WorkerOutcome::Error { .. }));
    }

    #[test]
    fn slot_snapshot_variants_round_trip() {
        let s = SlotSnapshot::Idle {
            pid: 42,
            call_count: 7,
            last_rss_bytes: 1024,
        };
        let s2 = s.clone();
        assert_eq!(s, s2);
    }

    /// Sanity check that the queue-depth helper plumbs through.
    #[test]
    fn queue_depth_default_doubles_pool_size() {
        let cfg = WarmProcessConfig {
            max_calls_per_worker: 1,
            max_rss_mb: 1,
            pool_size: 3,
            in_process: InProcessMode::Serial,
            max_queue_depth: None,
        };
        assert_eq!(cfg.effective_queue_depth(), 6);
    }
}
