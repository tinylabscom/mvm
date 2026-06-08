//! Host-memory-pressure eviction (Plan 170 WS-C).
//!
//! When free host RAM falls below the low watermark, *sleep* (never kill)
//! the least-recently-active VMs — LRU by `last_active` — until free RAM
//! recovers above the high watermark. Sleep + persist via the same path
//! as WS-B's idle reaper, so an evicted workspace survives and a later
//! wake brings it back.
//!
//! **Escalation order (two-stage, don't let them fight).** Ballooning is
//! the cheaper, transparent first lever — mvm already reclaims guest
//! memory via `BalloonController` / `run_balloon_loop` (`balloon_runtime`).
//! A pressure sweep should balloon-reclaim first and sleep-evict only once
//! ballooning is exhausted; this module owns the *eviction* selection, not
//! the balloon decision.
//!
//! This is the **mvm-side mechanism only**. It is pure-logic-first
//! (mirroring `reaper::sweep`): the watermark/LRU decisions take an
//! injected [`HostMem`] reading and a registry, so they test without a
//! real host or clock. mvmd's fleet scheduler may layer cross-host policy
//! on top via the same library; that seam is noted, not built here.

use chrono::{DateTime, Utc};
use mvm::vm::name_registry::VmNameRegistry;

/// A point-in-time host memory reading, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMem {
    pub total: u64,
    pub available: u64,
}

impl HostMem {
    /// Free RAM as a fraction of total, clamped to `[0.0, 1.0]`. A zero
    /// (or unreadable) total reports `1.0` — "no pressure" — so a bad
    /// reading never triggers eviction.
    pub fn free_fraction(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        (self.available as f64 / self.total as f64).clamp(0.0, 1.0)
    }
}

/// Free-RAM watermarks, expressed as fractions of total RAM in `(0, 1]`.
///
/// Bytes were rejected: `parse_human_size` is `u32` (caps ~4 GiB) and a
/// dev Mac has 16–192 GiB, so a fractional watermark is both safe and
/// consistent with the existing `used/total` pressure signal in
/// `balloon::SysinfoPressureSource`. Evict when free dips below `low`;
/// stop once free recovers to `high` (`low < high`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Watermarks {
    pub low: f64,
    pub high: f64,
}

/// Env var carrying the low watermark (free-RAM fraction). Pressure
/// eviction is **off** unless this is set to a valid fraction — opt-in,
/// matching WS-B's posture.
pub const MEM_LOW_WATERMARK_ENV: &str = "MVM_HOST_MEM_LOW_WATERMARK";
/// Env var carrying the high watermark (free-RAM fraction). Optional;
/// defaults to `low + 0.05` (capped below 1.0).
pub const MEM_HIGH_WATERMARK_ENV: &str = "MVM_HOST_MEM_HIGH_WATERMARK";

impl Watermarks {
    /// Build from explicit fractions, validating `0 < low < high <= 1`.
    /// `None` when the bounds are nonsensical (so a typo disables
    /// eviction rather than evicting on garbage).
    pub fn new(low: f64, high: f64) -> Option<Self> {
        if low.is_finite() && high.is_finite() && low > 0.0 && high > low && high <= 1.0 {
            Some(Self { low, high })
        } else {
            None
        }
    }

    /// Resolve from the environment. `None` (eviction off) unless
    /// [`MEM_LOW_WATERMARK_ENV`] parses to a valid fraction. The high
    /// watermark defaults to `low + 0.05` (capped at 0.99) when
    /// [`MEM_HIGH_WATERMARK_ENV`] is unset.
    pub fn from_env() -> Option<Self> {
        let low: f64 = std::env::var(MEM_LOW_WATERMARK_ENV)
            .ok()?
            .trim()
            .parse()
            .ok()?;
        let high = match std::env::var(MEM_HIGH_WATERMARK_ENV) {
            Ok(raw) => raw.trim().parse().ok()?,
            Err(_) => (low + 0.05).min(0.99),
        };
        Self::new(low, high)
    }
}

/// Is the host under memory pressure — free RAM below the low watermark?
pub fn under_pressure(mem: HostMem, w: Watermarks) -> bool {
    mem.free_fraction() < w.low
}

/// Has pressure been relieved — free RAM at or above the high watermark?
/// The eviction loop stops sleeping VMs once this holds.
pub fn relieved(mem: HostMem, w: Watermarks) -> bool {
    mem.free_fraction() >= w.high
}

/// VMs eligible for pressure eviction, ordered least-recently-active
/// first (the LRU eviction order). Eligible = `auto_resume && !paused`
/// (a pinned or already-slept VM is never pressure-evicted). Activity is
/// `last_active`, falling back to `registered_at`. A record whose
/// timestamps don't parse is sorted **last** (least evictable) so bad
/// data never makes a VM the first victim; ties break by name for
/// determinism.
pub fn lru_eviction_order(reg: &VmNameRegistry) -> Vec<String> {
    let mut eligible: Vec<(&String, Option<DateTime<Utc>>)> = reg
        .vms
        .iter()
        .filter(|(_, r)| r.auto_resume && !r.paused)
        .map(|(name, r)| {
            let raw = r.last_active.as_deref().unwrap_or(&r.registered_at);
            (name, mvm_core::util::time::parse_iso8601(raw))
        })
        .collect();

    eligible.sort_by(|a, b| match (a.1, b.1) {
        (Some(x), Some(y)) => x.cmp(&y).then_with(|| a.0.cmp(b.0)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.0.cmp(b.0),
    });

    eligible.into_iter().map(|(name, _)| name.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm::vm::name_registry::RegisterParams;

    fn mem(total: u64, available: u64) -> HostMem {
        HostMem { total, available }
    }

    #[test]
    fn free_fraction_handles_zero_total_as_no_pressure() {
        assert_eq!(mem(0, 0).free_fraction(), 1.0);
        assert_eq!(mem(100, 10).free_fraction(), 0.1);
        // Clamps a nonsensical available > total to 1.0.
        assert_eq!(mem(100, 500).free_fraction(), 1.0);
    }

    #[test]
    fn watermarks_new_rejects_bad_bounds() {
        assert!(Watermarks::new(0.1, 0.2).is_some());
        assert!(Watermarks::new(0.2, 0.1).is_none()); // high <= low
        assert!(Watermarks::new(0.0, 0.2).is_none()); // low <= 0
        assert!(Watermarks::new(0.1, 1.5).is_none()); // high > 1
        assert!(Watermarks::new(f64::NAN, 0.2).is_none());
    }

    #[test]
    fn under_pressure_and_relieved_track_watermarks() {
        let w = Watermarks::new(0.10, 0.20).unwrap();
        assert!(under_pressure(mem(100, 5), w)); // 5% free < 10%
        assert!(!under_pressure(mem(100, 15), w)); // 15% free >= 10%
        assert!(!relieved(mem(100, 15), w)); // 15% < 20%
        assert!(relieved(mem(100, 25), w)); // 25% >= 20%
    }

    #[test]
    fn lru_order_is_oldest_first_and_filters_ineligible() {
        let mut reg = VmNameRegistry::default();
        for n in ["new", "old", "mid", "paused", "pinned"] {
            reg.register_with_metadata(RegisterParams::minimal(n, "/tmp", "default"))
                .unwrap();
        }
        reg.touch_last_active("old", "2026-01-01T00:00:00Z")
            .unwrap();
        reg.touch_last_active("mid", "2026-01-01T01:00:00Z")
            .unwrap();
        reg.touch_last_active("new", "2026-01-01T02:00:00Z")
            .unwrap();
        // Ineligible: paused (already slept) + pinned (auto_resume off).
        reg.touch_last_active("paused", "2020-01-01T00:00:00Z")
            .unwrap();
        reg.set_paused("paused", true).unwrap();
        reg.touch_last_active("pinned", "2020-01-01T00:00:00Z")
            .unwrap();
        // Flip auto_resume off on "pinned".
        reg.vms.get_mut("pinned").unwrap().auto_resume = false;

        let order = lru_eviction_order(&reg);
        assert_eq!(order, vec!["old", "mid", "new"]);
    }

    #[test]
    fn lru_order_falls_back_to_registered_at_and_sorts_unparseable_last() {
        let mut reg = VmNameRegistry::default();
        // "touched" has an explicit old last_active; "fresh" relies on
        // registered_at (~now, newer); "bad" has an unparseable stamp.
        reg.register_with_metadata(RegisterParams::minimal("touched", "/tmp", "default"))
            .unwrap();
        reg.touch_last_active("touched", "2026-01-01T00:00:00Z")
            .unwrap();
        reg.register_with_metadata(RegisterParams::minimal("fresh", "/tmp", "default"))
            .unwrap();
        reg.register_with_metadata(RegisterParams::minimal("bad", "/tmp", "default"))
            .unwrap();
        reg.touch_last_active("bad", "not-a-timestamp").unwrap();

        let order = lru_eviction_order(&reg);
        assert_eq!(order.first().map(String::as_str), Some("touched"));
        assert_eq!(order.last().map(String::as_str), Some("bad"));
    }
}
