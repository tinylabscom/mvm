//! TTL reaper.
//!
//! Walks the persistent VM name registry on a tick, finds records
//! whose `expires_at` has elapsed, fires a teardown callback, and
//! deregisters them. Designed pure-logic-first so it's testable
//! without a real clock or a real Firecracker — the default daemon
//! adapter wraps it in a thread with system-clock and a
//! real backend `down` call.
//!
//! Jitter is applied to the *interval* between ticks, not the
//! per-record expiry: ±10 s jitter so an external observer cannot use
//! TTL expiry as a precise timing oracle. Per-record expiry stays exact.
//!
//! ## Consumer note
//!
//! The opt-in idle-sleep extension below (`with_idle_sleep` /
//! `IdleConfig` / `IdleSlept`) is an **unconsumed primitive**: nothing
//! in this repo constructs a `Reaper` outside tests (the local `mvmctl`
//! path is daemon-free), and mvmd does *not* depend on this crate — it
//! implements idle / host-memory-pressure / wake natively in its own
//! model (`mvmd-agent/host_pressure.rs`,
//! `mvmd-coordinator/{idle,wake,wake_on_demand}.rs`). The TTL path is the
//! load-bearing part; the idle hook is retained as additive,
//! behavior-preserving infrastructure should a resident consumer ever want
//! it.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use mvm::vm::name_registry::{VmNameRegistry, VmRegistration};
use rand::Rng;

/// Default tick interval — ticks fire every `INTERVAL ± JITTER`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum jitter applied to each tick interval.
pub const DEFAULT_JITTER: Duration = Duration::from_secs(10);

/// Lower bound on jittered interval, defends against jitter > interval.
const MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Outcome of a single `tick()` for one VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReapOutcome {
    /// VM had no TTL or its TTL has not yet elapsed, and it is not idle
    /// (or idle-sleep is not configured).
    Skipped,
    /// VM was reaped (teardown invoked, registry record removed).
    Reaped { name: String },
    /// VM had an unparseable `expires_at`; left in place.
    /// Surfaced as a single audit event so operators can investigate
    /// rather than letting the bad record cause silent skips forever.
    MalformedExpiry { name: String, raw: String },
    /// VM expired, but the teardown callback returned an error. The
    /// registry record is *kept* so the next tick retries.
    TeardownFailed { name: String, error: String },
    /// VM was idle past its idle-timeout and got slept (sleep callback
    /// invoked, registry record kept with `paused = true`).
    IdleSlept { name: String },
    /// VM was idle, but the sleep callback returned an error. The record
    /// is left running (not paused) so the next tick retries.
    SleepFailed { name: String, error: String },
}

/// Callback invoked when a VM's TTL has elapsed and the reaper is
/// about to deregister it. Returning `Err` keeps the registry record
/// in place so the next tick retries — useful for transient backend
/// failures.
pub type TeardownFn = Box<dyn Fn(&str, &VmRegistration) -> Result<(), String> + Send + Sync>;

/// Callback invoked when a VM has been idle past its idle-timeout and the
/// reaper is about to put it to sleep (drain/pause — the *trigger*, not a
/// new sleep mechanism). The implementation performs the
/// backend-appropriate sleep (drain+snapshot for snapshot-capable backends,
/// clean stop with data disk + TAP retained for libkrun).
/// Returning `Err` leaves the VM running so the next tick retries; the
/// reaper itself flips `paused = true` in the registry on success.
pub type SleepFn = Box<dyn Fn(&str, &VmRegistration) -> Result<(), String> + Send + Sync>;

/// Per-VM tag whose value (whole seconds) overrides the global idle
/// timeout for one workload — e.g. a long-lived service tagged
/// `idle_timeout_secs=0` opts out, a scratch box tags a tighter bound.
pub const IDLE_TIMEOUT_TAG: &str = "idle_timeout_secs";

/// Env var carrying the global idle timeout (whole seconds). Unset or
/// unparseable → idle-sleep is off (opt-in), so a plain `mvmctl start` is
/// unchanged unless the operator asks for density.
pub const IDLE_TIMEOUT_ENV: &str = "MVM_IDLE_TIMEOUT";

/// Idle-sleep configuration the reaper consults per tick. Held as
/// `Option` on [`Reaper`] so the default (TTL-only) path is byte-for-byte
/// the pre-idle behavior — mvmd and any other consumer that builds a
/// `Reaper::new(...)` without opting in see no change.
pub struct IdleConfig {
    /// Backend-appropriate sleep callback (see [`SleepFn`]).
    pub sleep: SleepFn,
    /// Global idle timeout, applied to any VM without an
    /// [`IDLE_TIMEOUT_TAG`] override. `None` = no global default (idle
    /// fires only for VMs carrying the per-VM tag).
    pub default_timeout: Option<Duration>,
}

/// Read the global idle timeout from [`IDLE_TIMEOUT_ENV`] (whole
/// seconds). `None` when unset, empty, unparseable, or zero — zero means
/// "off", matching the opt-in posture.
pub fn global_idle_timeout_from_env() -> Option<Duration> {
    let raw = std::env::var(IDLE_TIMEOUT_ENV).ok()?;
    let secs: u64 = raw.trim().parse().ok()?;
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Resolve the effective idle timeout for one record: the per-VM
/// [`IDLE_TIMEOUT_TAG`] override if present and parseable, else
/// `default`. A tag value of `0` (or a parseable override) wins over the
/// default — including `0` to explicitly opt a workload out.
pub fn resolve_idle_timeout(reg: &VmRegistration, default: Option<Duration>) -> Option<Duration> {
    if let Some(raw) = reg.tags.get(IDLE_TIMEOUT_TAG) {
        return raw
            .trim()
            .parse::<u64>()
            .ok()
            .and_then(|secs| (secs > 0).then(|| Duration::from_secs(secs)));
    }
    default
}

/// Elapsed time since the record was last active. Keys off `last_active`,
/// falling back to `registered_at` when never touched (so a freshly
/// registered VM isn't instantly idle). `None` if neither timestamp
/// parses or the timestamp is in the future (clock skew).
pub fn idle_elapsed(reg: &VmRegistration, now: DateTime<Utc>) -> Option<Duration> {
    let raw = reg.last_active.as_deref().unwrap_or(&reg.registered_at);
    let since = mvm_core::util::time::parse_iso8601(raw)?;
    (now - since).to_std().ok()
}

pub struct Reaper {
    registry_path: PathBuf,
    teardown: TeardownFn,
    idle: Option<IdleConfig>,
}

impl Reaper {
    pub fn new(registry_path: PathBuf, teardown: TeardownFn) -> Self {
        Self {
            registry_path,
            teardown,
            idle: None,
        }
    }

    /// Opt into activity-driven idle-sleep. Without this
    /// the reaper is TTL-only, exactly as before. Builder-style so the
    /// existing `Reaper::new(path, teardown)` call sites are unchanged.
    pub fn with_idle_sleep(mut self, sleep: SleepFn, default_timeout: Option<Duration>) -> Self {
        self.idle = Some(IdleConfig {
            sleep,
            default_timeout,
        });
        self
    }

    /// Run a single sweep. Returns the per-VM outcomes; persists the
    /// updated registry to disk only if something actually changed (a
    /// record was reaped, or an idle VM was slept and marked paused).
    pub fn tick(&self, now: DateTime<Utc>) -> Vec<ReapOutcome> {
        let mut registry = match VmNameRegistry::load(&self.registry_path) {
            Ok(r) => r,
            // I/O failure is treated as "no registry" — we don't want a
            // missing file to crash the supervisor; the reaper is
            // best-effort.
            Err(_) => return Vec::new(),
        };
        let outcomes = sweep(&mut registry, now, &self.teardown, self.idle.as_ref());

        // Only re-save the registry if something actually changed.
        if outcomes.iter().any(|o| {
            matches!(
                o,
                ReapOutcome::Reaped { .. } | ReapOutcome::IdleSlept { .. }
            )
        }) {
            let _ = registry.save(&self.registry_path);
        }
        outcomes
    }
}

/// Pure-logic sweep — testable without filesystem.
///
/// Per record, in precedence order: a malformed `expires_at` is reported
/// and left in place; an **elapsed** TTL hard-reaps (teardown + deregister)
/// as it always has; otherwise, when idle-sleep is configured, an idle VM
/// past its (per-VM or global) timeout is *slept* (sleep callback + flip
/// `paused = true`, record kept) so a later wake can bring it back. TTL
/// wins over idle — a VM whose TTL has elapsed is reaped, not slept.
fn sweep(
    registry: &mut VmNameRegistry,
    now: DateTime<Utc>,
    teardown: &TeardownFn,
    idle: Option<&IdleConfig>,
) -> Vec<ReapOutcome> {
    let mut outcomes = Vec::new();
    let mut to_remove = Vec::new();
    let mut to_pause = Vec::new();

    // Snapshot the iteration so we can mutate `registry.vms` after.
    let snapshot: BTreeMap<String, VmRegistration> = registry
        .vms
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    for (name, reg) in snapshot {
        // ── TTL (terminal, wins over idle) ──────────────────────────
        if let Some(raw) = reg.expires_at.as_deref() {
            let Some(expires) = mvm_core::util::time::parse_iso8601(raw) else {
                outcomes.push(ReapOutcome::MalformedExpiry {
                    name: name.clone(),
                    raw: raw.to_string(),
                });
                continue;
            };
            if expires <= now {
                match teardown(&name, &reg) {
                    Ok(()) => {
                        to_remove.push(name.clone());
                        outcomes.push(ReapOutcome::Reaped { name });
                    }
                    Err(e) => outcomes.push(ReapOutcome::TeardownFailed { name, error: e }),
                }
                continue;
            }
        }

        // ── Idle-sleep (opt-in; TTL not yet elapsed) ────────────────
        if let Some(cfg) = idle
            && reg.auto_resume
            && !reg.paused
            && let Some(timeout) = resolve_idle_timeout(&reg, cfg.default_timeout)
            && idle_elapsed(&reg, now).is_some_and(|e| e > timeout)
        {
            match (cfg.sleep)(&name, &reg) {
                Ok(()) => {
                    to_pause.push(name.clone());
                    outcomes.push(ReapOutcome::IdleSlept { name });
                }
                Err(e) => outcomes.push(ReapOutcome::SleepFailed { name, error: e }),
            }
            continue;
        }

        outcomes.push(ReapOutcome::Skipped);
    }

    for name in to_remove {
        registry.deregister(&name);
    }
    // Mark slept VMs paused so the next tick skips them (idle requires
    // `!paused`) and `mvmctl ls` shows them as sleeping until woken.
    for name in to_pause {
        let _ = registry.set_paused(&name, true);
    }
    outcomes
}

/// Compute the next jittered tick interval. Public so tests can
/// drive it deterministically with a seeded RNG.
pub fn jittered_interval<R: Rng>(rng: &mut R, base: Duration, jitter: Duration) -> Duration {
    if jitter.is_zero() {
        return base;
    }
    // Pick a signed offset in `[-jitter, +jitter]`.
    let span = jitter.as_millis() as i64;
    let offset = rng.gen_range(-span..=span);
    let base_ms = base.as_millis() as i64;
    let total = (base_ms + offset).max(MIN_INTERVAL.as_millis() as i64);
    Duration::from_millis(total as u64)
}

/// A teardown callback that just deregisters (does not call any
/// backend). Used by integration tests and as the default; the
/// real backend-aware teardown lands when `Supervisor::launch` does.
pub fn deregister_only_teardown() -> TeardownFn {
    Box::new(|_name: &str, _reg: &VmRegistration| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm::vm::name_registry::RegisterParams;
    use mvm_core::util::test_env::TestEnv;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn registry_with_one(expires_at: Option<&str>) -> VmNameRegistry {
        let mut reg = VmNameRegistry::default();
        reg.register_with_metadata(RegisterParams {
            name: "vm1",
            vm_dir: "/tmp/vm1",
            network: "default",
            guest_ip: None,
            slot_index: 0,
            tags: BTreeMap::new(),
            expires_at: expires_at.map(str::to_string),
            auto_resume: true,
        })
        .unwrap();
        reg
    }

    #[test]
    fn sweep_skips_no_ttl() {
        let mut reg = registry_with_one(None);
        let now = Utc::now();
        let teardown = deregister_only_teardown();
        let outcomes = sweep(&mut reg, now, &teardown, None);
        assert_eq!(outcomes, vec![ReapOutcome::Skipped]);
        assert!(reg.lookup("vm1").is_some());
    }

    #[test]
    fn sweep_skips_future_ttl() {
        let now = Utc::now();
        let future = now + chrono::Duration::seconds(60);
        let raw = future.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut reg = registry_with_one(Some(&raw));
        let teardown = deregister_only_teardown();
        let outcomes = sweep(&mut reg, now, &teardown, None);
        assert_eq!(outcomes, vec![ReapOutcome::Skipped]);
        assert!(reg.lookup("vm1").is_some());
    }

    #[test]
    fn sweep_reaps_past_ttl() {
        let now = Utc::now();
        let past = now - chrono::Duration::seconds(60);
        let raw = past.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut reg = registry_with_one(Some(&raw));
        let teardown = deregister_only_teardown();
        let outcomes = sweep(&mut reg, now, &teardown, None);
        assert_eq!(
            outcomes,
            vec![ReapOutcome::Reaped {
                name: "vm1".to_string()
            }]
        );
        assert!(reg.lookup("vm1").is_none());
    }

    #[test]
    fn sweep_reports_malformed_expiry_without_removing() {
        let mut reg = registry_with_one(Some("not a real timestamp"));
        let now = Utc::now();
        let teardown = deregister_only_teardown();
        let outcomes = sweep(&mut reg, now, &teardown, None);
        assert_eq!(
            outcomes,
            vec![ReapOutcome::MalformedExpiry {
                name: "vm1".to_string(),
                raw: "not a real timestamp".to_string()
            }]
        );
        // Record stays in place so it's visible in `mvmctl ls` and an
        // operator can investigate.
        assert!(reg.lookup("vm1").is_some());
    }

    #[test]
    fn sweep_keeps_record_when_teardown_fails() {
        let now = Utc::now();
        let past = now - chrono::Duration::seconds(60);
        let raw = past.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut reg = registry_with_one(Some(&raw));
        let teardown: TeardownFn = Box::new(|_, _| Err("backend down".to_string()));
        let outcomes = sweep(&mut reg, now, &teardown, None);
        assert!(matches!(
            outcomes.as_slice(),
            [ReapOutcome::TeardownFailed { name, .. }] if name == "vm1"
        ));
        // Next tick will retry — record kept on disk.
        assert!(reg.lookup("vm1").is_some());
    }

    #[test]
    fn sweep_invokes_teardown_with_registration() {
        let now = Utc::now();
        let past = now - chrono::Duration::seconds(60);
        let raw = past.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut reg = registry_with_one(Some(&raw));
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let teardown: TeardownFn = Box::new(move |name, registration| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            assert_eq!(name, "vm1");
            assert_eq!(registration.vm_dir, "/tmp/vm1");
            Ok(())
        });
        let _ = sweep(&mut reg, now, &teardown, None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn jittered_interval_stays_in_band() {
        let mut rng = StdRng::seed_from_u64(0xc0ffee);
        for _ in 0..256 {
            let d = jittered_interval(&mut rng, Duration::from_secs(30), Duration::from_secs(10));
            assert!(d >= Duration::from_secs(20));
            assert!(d <= Duration::from_secs(40));
        }
    }

    #[test]
    fn jittered_interval_zero_jitter_is_base() {
        let mut rng = StdRng::seed_from_u64(0);
        let d = jittered_interval(&mut rng, Duration::from_secs(30), Duration::ZERO);
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn jittered_interval_clamps_to_minimum() {
        let mut rng = StdRng::seed_from_u64(0);
        // jitter > base would otherwise drive the interval negative.
        let d = jittered_interval(
            &mut rng,
            Duration::from_millis(500),
            Duration::from_secs(60),
        );
        assert!(d >= MIN_INTERVAL);
    }

    #[test]
    fn reaper_persists_registry_after_reap() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vm-names.json");
        let now = Utc::now();
        let past = now - chrono::Duration::seconds(60);
        let raw = past.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let reg = registry_with_one(Some(&raw));
        reg.save(&path).unwrap();

        let reaper = Reaper::new(path.clone(), deregister_only_teardown());
        let outcomes = reaper.tick(now);
        assert!(matches!(outcomes.as_slice(), [ReapOutcome::Reaped { .. }]));

        // Reload from disk: the record should be gone.
        let reloaded = VmNameRegistry::load(&path).unwrap();
        assert!(reloaded.lookup("vm1").is_none());
    }

    #[test]
    fn reaper_does_not_save_when_nothing_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vm-names.json");
        let reg = registry_with_one(None);
        reg.save(&path).unwrap();

        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        // Allow the FS clock to tick before the next save would race.
        std::thread::sleep(Duration::from_millis(10));

        let reaper = Reaper::new(path.clone(), deregister_only_teardown());
        let _ = reaper.tick(Utc::now());

        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "registry mtime changed without a reap"
        );
    }

    #[test]
    fn reaper_with_missing_registry_returns_empty() {
        let path = PathBuf::from("/definitely/does/not/exist/vm-names.json");
        let reaper = Reaper::new(path, deregister_only_teardown());
        assert!(reaper.tick(Utc::now()).is_empty());
    }

    // -------- Idle-sleep --------

    /// One registration with controllable activity/auto-resume/paused/tag.
    fn idle_registry(
        last_active_secs_ago: i64,
        auto_resume: bool,
        paused: bool,
        tag: Option<&str>,
    ) -> (VmNameRegistry, DateTime<Utc>) {
        let now = Utc::now();
        let mut tags = BTreeMap::new();
        if let Some(t) = tag {
            tags.insert(IDLE_TIMEOUT_TAG.to_string(), t.to_string());
        }
        let mut reg = VmNameRegistry::default();
        reg.register_with_metadata(RegisterParams {
            name: "vm1",
            vm_dir: "/tmp/vm1",
            network: "default",
            guest_ip: None,
            slot_index: 0,
            tags,
            expires_at: None,
            auto_resume,
        })
        .unwrap();
        let la = (now - chrono::Duration::seconds(last_active_secs_ago))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        reg.touch_last_active("vm1", la).unwrap();
        if paused {
            reg.set_paused("vm1", true).unwrap();
        }
        (reg, now)
    }

    /// A sleep callback that counts calls; never fails.
    fn counting_sleep(counter: Arc<AtomicUsize>) -> SleepFn {
        Box::new(move |_name, _reg| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn idle_cfg(sleep: SleepFn, default_secs: Option<u64>) -> IdleConfig {
        IdleConfig {
            sleep,
            default_timeout: default_secs.map(Duration::from_secs),
        }
    }

    #[test]
    fn idle_elapsed_prefers_last_active_then_registered_at() {
        let now = Utc::now();
        let mut reg = registry_with_one(None);
        // No last_active → falls back to registered_at (~now) → tiny elapsed.
        let e = idle_elapsed(reg.lookup("vm1").unwrap(), now).unwrap();
        assert!(e < Duration::from_secs(5));
        // With last_active 120s ago → ~120s elapsed.
        let la = (now - chrono::Duration::seconds(120))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        reg.touch_last_active("vm1", la).unwrap();
        let e = idle_elapsed(reg.lookup("vm1").unwrap(), now).unwrap();
        assert!(
            e >= Duration::from_secs(115) && e <= Duration::from_secs(125),
            "{e:?}"
        );
    }

    #[test]
    fn resolve_idle_timeout_tag_overrides_default() {
        let (reg, _) = idle_registry(0, true, false, Some("30"));
        assert_eq!(
            resolve_idle_timeout(reg.lookup("vm1").unwrap(), Some(Duration::from_secs(600))),
            Some(Duration::from_secs(30))
        );
        // Tag "0" opts the workload out even when a global default exists.
        let (reg, _) = idle_registry(0, true, false, Some("0"));
        assert_eq!(
            resolve_idle_timeout(reg.lookup("vm1").unwrap(), Some(Duration::from_secs(600))),
            None
        );
        // No tag → the default applies.
        let (reg, _) = idle_registry(0, true, false, None);
        assert_eq!(
            resolve_idle_timeout(reg.lookup("vm1").unwrap(), Some(Duration::from_secs(600))),
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn sweep_sleeps_idle_vm_and_marks_paused() {
        let (mut reg, now) = idle_registry(120, true, false, None);
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = idle_cfg(counting_sleep(Arc::clone(&calls)), Some(60));
        let outcomes = sweep(&mut reg, now, &deregister_only_teardown(), Some(&cfg));
        assert_eq!(
            outcomes,
            vec![ReapOutcome::IdleSlept {
                name: "vm1".to_string()
            }]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Record kept, now paused — so the next tick won't re-sleep it.
        assert!(reg.lookup("vm1").unwrap().paused);
    }

    #[test]
    fn sweep_idle_run_twice_sleeps_once() {
        let (mut reg, now) = idle_registry(120, true, false, None);
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = idle_cfg(counting_sleep(Arc::clone(&calls)), Some(60));
        let _ = sweep(&mut reg, now, &deregister_only_teardown(), Some(&cfg));
        let second = sweep(&mut reg, now, &deregister_only_teardown(), Some(&cfg));
        assert_eq!(
            second,
            vec![ReapOutcome::Skipped],
            "paused VM must not re-sleep"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sweep_does_not_sleep_when_not_yet_idle() {
        let (mut reg, now) = idle_registry(10, true, false, None);
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = idle_cfg(counting_sleep(Arc::clone(&calls)), Some(60));
        let outcomes = sweep(&mut reg, now, &deregister_only_teardown(), Some(&cfg));
        assert_eq!(outcomes, vec![ReapOutcome::Skipped]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sweep_never_sleeps_when_auto_resume_false() {
        let (mut reg, now) = idle_registry(120, false, false, None);
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = idle_cfg(counting_sleep(Arc::clone(&calls)), Some(60));
        let outcomes = sweep(&mut reg, now, &deregister_only_teardown(), Some(&cfg));
        assert_eq!(outcomes, vec![ReapOutcome::Skipped]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sweep_idle_off_by_default_without_config() {
        // No IdleConfig → idle never fires even for a long-idle VM.
        let (mut reg, now) = idle_registry(99999, true, false, None);
        let outcomes = sweep(&mut reg, now, &deregister_only_teardown(), None);
        assert_eq!(outcomes, vec![ReapOutcome::Skipped]);
        assert!(!reg.lookup("vm1").unwrap().paused);
    }

    #[test]
    fn sweep_idle_tag_enables_without_global_default() {
        // default_timeout None, but the per-VM tag sets 60s → sleeps.
        let (mut reg, now) = idle_registry(120, true, false, Some("60"));
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = idle_cfg(counting_sleep(Arc::clone(&calls)), None);
        let outcomes = sweep(&mut reg, now, &deregister_only_teardown(), Some(&cfg));
        assert_eq!(
            outcomes,
            vec![ReapOutcome::IdleSlept {
                name: "vm1".to_string()
            }]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn sweep_ttl_wins_over_idle() {
        // VM is both expired (TTL) and idle — TTL reaps, idle is not invoked.
        let now = Utc::now();
        let past = (now - chrono::Duration::seconds(60))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let mut reg = registry_with_one(Some(&past));
        let la = (now - chrono::Duration::seconds(120))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        reg.touch_last_active("vm1", la).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = idle_cfg(counting_sleep(Arc::clone(&calls)), Some(60));
        let outcomes = sweep(&mut reg, now, &deregister_only_teardown(), Some(&cfg));
        assert_eq!(
            outcomes,
            vec![ReapOutcome::Reaped {
                name: "vm1".to_string()
            }]
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "idle sleep must not fire when TTL reaps"
        );
        assert!(reg.lookup("vm1").is_none());
    }

    #[test]
    fn sweep_sleep_failure_keeps_vm_running() {
        let (mut reg, now) = idle_registry(120, true, false, None);
        let cfg = IdleConfig {
            sleep: Box::new(|_, _| Err("drain timed out".to_string())),
            default_timeout: Some(Duration::from_secs(60)),
        };
        let outcomes = sweep(&mut reg, now, &deregister_only_teardown(), Some(&cfg));
        assert!(matches!(
            outcomes.as_slice(),
            [ReapOutcome::SleepFailed { name, .. }] if name == "vm1"
        ));
        // Left running for the next tick to retry — not paused.
        assert!(!reg.lookup("vm1").unwrap().paused);
    }

    #[test]
    fn global_idle_timeout_from_env_parses_and_treats_zero_as_off() {
        let mut env = TestEnv::new();
        env.set(IDLE_TIMEOUT_ENV, "45");
        assert_eq!(
            global_idle_timeout_from_env(),
            Some(Duration::from_secs(45))
        );
        env.set(IDLE_TIMEOUT_ENV, "0");
        assert_eq!(global_idle_timeout_from_env(), None);
        env.set(IDLE_TIMEOUT_ENV, "garbage");
        assert_eq!(global_idle_timeout_from_env(), None);
        env.remove(IDLE_TIMEOUT_ENV);
        assert_eq!(global_idle_timeout_from_env(), None);
    }
}
