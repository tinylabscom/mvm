//! TTL reaper — Wave 1, Control 5 of the filesystem-volumes plan.
//!
//! Walks the persistent VM name registry on a tick, finds records
//! whose `expires_at` has elapsed, fires a teardown callback, and
//! deregisters them. Designed pure-logic-first so it's testable
//! without a real clock or a real Firecracker — the default daemon
//! adapter (Wave 3) wraps it in a thread with system-clock and a
//! real backend `down` call.
//!
//! Jitter is applied to the *interval* between ticks, not the
//! per-record expiry: G6 in the plan calls for ±10 s jitter so an
//! external observer cannot use TTL expiry as a precise timing
//! oracle. Per-record expiry stays exact.

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
    /// VM had no TTL or its TTL has not yet elapsed.
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
}

/// Callback invoked when a VM's TTL has elapsed and the reaper is
/// about to deregister it. Returning `Err` keeps the registry record
/// in place so the next tick retries — useful for transient backend
/// failures.
pub type TeardownFn = Box<dyn Fn(&str, &VmRegistration) -> Result<(), String> + Send + Sync>;

pub struct Reaper {
    registry_path: PathBuf,
    teardown: TeardownFn,
}

impl Reaper {
    pub fn new(registry_path: PathBuf, teardown: TeardownFn) -> Self {
        Self {
            registry_path,
            teardown,
        }
    }

    /// Run a single sweep. Returns the per-VM outcomes; persists the
    /// updated registry to disk only if at least one record was
    /// removed.
    pub fn tick(&self, now: DateTime<Utc>) -> Vec<ReapOutcome> {
        let mut registry = match VmNameRegistry::load(&self.registry_path) {
            Ok(r) => r,
            // I/O failure is treated as "no registry" — we don't want a
            // missing file to crash the supervisor; the reaper is
            // best-effort.
            Err(_) => return Vec::new(),
        };
        let outcomes = sweep(&mut registry, now, &self.teardown);

        // Only re-save the registry if something actually changed.
        if outcomes
            .iter()
            .any(|o| matches!(o, ReapOutcome::Reaped { .. }))
        {
            let _ = registry.save(&self.registry_path);
        }
        outcomes
    }
}

/// Pure-logic sweep — testable without filesystem.
fn sweep(
    registry: &mut VmNameRegistry,
    now: DateTime<Utc>,
    teardown: &TeardownFn,
) -> Vec<ReapOutcome> {
    let mut outcomes = Vec::new();
    let mut to_remove = Vec::new();

    // Snapshot the iteration so we can mutate `registry.vms` after.
    let snapshot: BTreeMap<String, VmRegistration> = registry
        .vms
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    for (name, reg) in snapshot {
        let Some(raw) = reg.expires_at.as_deref() else {
            outcomes.push(ReapOutcome::Skipped);
            continue;
        };
        let Some(expires) = mvm_core::util::time::parse_iso8601(raw) else {
            outcomes.push(ReapOutcome::MalformedExpiry {
                name: name.clone(),
                raw: raw.to_string(),
            });
            continue;
        };
        if expires > now {
            outcomes.push(ReapOutcome::Skipped);
            continue;
        }
        match teardown(&name, &reg) {
            Ok(()) => {
                to_remove.push(name.clone());
                outcomes.push(ReapOutcome::Reaped { name });
            }
            Err(e) => outcomes.push(ReapOutcome::TeardownFailed { name, error: e }),
        }
    }
    for name in to_remove {
        registry.deregister(&name);
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
/// backend). Used by integration tests and as the wave-1 default; the
/// real backend-aware teardown lands when `Supervisor::launch` does.
pub fn deregister_only_teardown() -> TeardownFn {
    Box::new(|_name: &str, _reg: &VmRegistration| Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm::vm::name_registry::RegisterParams;
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
        let outcomes = sweep(&mut reg, now, &teardown);
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
        let outcomes = sweep(&mut reg, now, &teardown);
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
        let outcomes = sweep(&mut reg, now, &teardown);
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
        let outcomes = sweep(&mut reg, now, &teardown);
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
        let outcomes = sweep(&mut reg, now, &teardown);
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
        let _ = sweep(&mut reg, now, &teardown);
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
}
