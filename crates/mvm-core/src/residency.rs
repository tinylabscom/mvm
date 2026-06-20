//! Residency policy: how warm the standby pool is kept. One knob — a warm
//! target plus an idle timeout — resolved from `MVM_RESIDENCY` or a per-host
//! default. The demotion-on-idle mechanism lives elsewhere; this module only
//! resolves and describes the policy.

use std::time::Duration;

pub const MVM_RESIDENCY_ENV: &str = "MVM_RESIDENCY";

/// Which residency a policy expresses — the typed discriminant behind the three
/// constructors, so callers branch on intent rather than the display label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidencyKind {
    Warm,
    Parked,
    Cold,
}

/// How warm the standby pool is kept. `warm_target` standbys are held live;
/// `idle_timeout`, when set, is how long a warm standby may sit idle before it
/// is eligible for demotion to a parked snapshot (demotion handled elsewhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidencyPolicy {
    warm_target: u32,
    idle_timeout: Option<Duration>,
    label: &'static str,
    kind: ResidencyKind,
}

impl ResidencyPolicy {
    /// Keep one standby warm; demote to parked after 20 minutes idle.
    pub fn always_warm() -> Self {
        Self {
            warm_target: 1,
            idle_timeout: Some(Duration::from_secs(20 * 60)),
            label: "always-warm",
            kind: ResidencyKind::Warm,
        }
    }
    /// Hold nothing warm; resume from a parked snapshot on demand.
    pub fn parked() -> Self {
        Self {
            warm_target: 0,
            idle_timeout: None,
            label: "parked",
            kind: ResidencyKind::Parked,
        }
    }
    /// Hold nothing warm and keep no snapshot; cold-boot on demand.
    pub fn cold() -> Self {
        Self {
            warm_target: 0,
            idle_timeout: None,
            label: "cold",
            kind: ResidencyKind::Cold,
        }
    }

    pub fn warm_target(&self) -> u32 {
        self.warm_target
    }
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }
    pub fn label(&self) -> &'static str {
        self.label
    }
    pub fn kind(&self) -> ResidencyKind {
        self.kind
    }
    /// Whether builds may use (and keep) the persistent builder VM under this
    /// policy. Only `Cold` opts out — it routes builds through the single-shot
    /// builder that boots and tears down per build.
    pub fn allows_persistent_builder(&self) -> bool {
        !matches!(self.kind, ResidencyKind::Cold)
    }
}

/// Where a resolved policy came from — for observability in `doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidencySource {
    EnvOverride,
    AutoDetect,
}

fn parse_env_residency(raw: &str) -> Option<ResidencyPolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "warm" | "always-warm" => Some(ResidencyPolicy::always_warm()),
        "parked" => Some(ResidencyPolicy::parked()),
        "cold" => Some(ResidencyPolicy::cold()),
        _ => None,
    }
}

fn host_default_for(is_vz_default_tier: bool) -> ResidencyPolicy {
    if is_vz_default_tier {
        ResidencyPolicy::always_warm()
    } else {
        ResidencyPolicy::parked()
    }
}

/// The warm-pool size to use: an explicit request wins; otherwise the resolved
/// residency policy's warm target.
pub fn effective_warm_pool_size(explicit: Option<u32>) -> u32 {
    match explicit {
        Some(n) => n,
        None => resolve_residency().0.warm_target(),
    }
}

/// Resolve the active policy: `MVM_RESIDENCY` if set to a known value, else the
/// per-host default. Returns the policy and which source decided it.
pub fn resolve_residency() -> (ResidencyPolicy, ResidencySource) {
    if let Ok(raw) = std::env::var(MVM_RESIDENCY_ENV)
        && !raw.trim().is_empty()
    {
        if let Some(p) = parse_env_residency(&raw) {
            return (p, ResidencySource::EnvOverride);
        }
        eprintln!(
            "[mvm] warning: unrecognised {MVM_RESIDENCY_ENV}={raw:?} (expected warm|parked|cold); using auto-detect"
        );
    }
    let is_tier = crate::platform::current().is_vz_default_tier();
    (host_default_for(is_tier), ResidencySource::AutoDetect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_warm_keeps_one_warm_with_idle_timeout() {
        let p = ResidencyPolicy::always_warm();
        assert_eq!(p.warm_target(), 1);
        assert_eq!(p.idle_timeout(), Some(Duration::from_secs(20 * 60)));
        assert_eq!(p.label(), "always-warm");
    }

    #[test]
    fn parked_holds_no_warm_and_no_idle_timer() {
        let p = ResidencyPolicy::parked();
        assert_eq!(p.warm_target(), 0);
        assert_eq!(p.idle_timeout(), None);
        assert_eq!(p.label(), "parked");
    }

    #[test]
    fn cold_holds_no_warm() {
        assert_eq!(ResidencyPolicy::cold().warm_target(), 0);
        assert_eq!(ResidencyPolicy::cold().label(), "cold");
        assert_eq!(ResidencyPolicy::cold().idle_timeout(), None);
    }

    #[test]
    fn env_override_wins_case_insensitive() {
        assert_eq!(
            parse_env_residency("warm"),
            Some(ResidencyPolicy::always_warm())
        );
        assert_eq!(
            parse_env_residency("  PARKED "),
            Some(ResidencyPolicy::parked())
        );
        assert_eq!(parse_env_residency("Cold"), Some(ResidencyPolicy::cold()));
        assert_eq!(
            parse_env_residency("always-warm"),
            Some(ResidencyPolicy::always_warm())
        );
    }

    #[test]
    fn unrecognised_or_empty_env_is_none() {
        assert_eq!(parse_env_residency(""), None);
        assert_eq!(parse_env_residency("hot"), None);
    }

    #[test]
    fn host_default_is_warm_on_vz_tier_parked_otherwise() {
        assert_eq!(host_default_for(true), ResidencyPolicy::always_warm());
        assert_eq!(host_default_for(false), ResidencyPolicy::parked());
    }

    #[test]
    fn explicit_warm_pool_size_overrides_policy() {
        assert_eq!(effective_warm_pool_size(Some(3)), 3);
        assert_eq!(effective_warm_pool_size(Some(0)), 0);
    }

    #[test]
    fn none_warm_pool_size_falls_back_to_resolved_policy() {
        assert_eq!(
            effective_warm_pool_size(None),
            resolve_residency().0.warm_target()
        );
    }

    #[test]
    fn kind_matches_constructor() {
        assert_eq!(ResidencyPolicy::always_warm().kind(), ResidencyKind::Warm);
        assert_eq!(ResidencyPolicy::parked().kind(), ResidencyKind::Parked);
        assert_eq!(ResidencyPolicy::cold().kind(), ResidencyKind::Cold);
    }

    #[test]
    fn only_cold_disallows_the_persistent_builder() {
        assert!(ResidencyPolicy::always_warm().allows_persistent_builder());
        assert!(ResidencyPolicy::parked().allows_persistent_builder());
        assert!(!ResidencyPolicy::cold().allows_persistent_builder());
    }
}
