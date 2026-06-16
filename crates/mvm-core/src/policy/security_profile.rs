//! Named security profiles: a per-seam capability matrix over the three
//! workload seams — the [`SeccompTier`], the egress [`NetworkPreset`], and
//! whether memory snapshots are allowed — plus whether the profile may be
//! **deployed**.
//!
//! The model is deliberately binary, not a strictness gradient:
//!
//! * [`PRODUCTION`] is the **default**. It is the production-ready posture
//!   with the highest practical security — every seam locked (seccomp floor,
//!   deny-all egress, no snapshot) — and it is the only deployable profile.
//!   You opt *up* into capability explicitly (per-seam flags), never down by
//!   accident.
//! * [`DEV`] is a development-only convenience: looser seams for inner-loop
//!   ergonomics, and `deployable = false` so it **can never reach
//!   production**. Because it is structurally non-deployable, it is allowed to
//!   be loose; a deployable profile never is (see [`SecurityProfile::is_bounded`]).
//!
//! The default when `--security-profile` is unset is always [`PRODUCTION`] —
//! a workload is production-safe unless its author explicitly selects `dev`.

use std::fmt;

use crate::crypto::seccomp::SeccompTier;
use crate::policy::network_policy::NetworkPreset;

/// The resolved per-seam dispositions a named profile selects. Copy so call
/// sites can pass it by value into each seam's enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityProfile {
    /// Stable lowercase canonical name (`production` / `dev`).
    pub name: &'static str,
    /// Seccomp tier applied to the workload's services.
    pub seccomp: SeccompTier,
    /// Egress posture (the network preset the gateway enforces).
    pub egress: NetworkPreset,
    /// Whether a memory-state snapshot may be taken of this workload.
    pub snapshot_allowed: bool,
    /// Whether a workload using this profile may be deployed (run in a
    /// production / sealed context). `production` is deployable; `dev` is
    /// development-only and must never deploy.
    pub deployable: bool,
}

impl SecurityProfile {
    /// A bounded posture keeps a real seccomp filter and a non-open egress
    /// allow-list. Every *deployable* profile must be bounded; only the
    /// non-deployable `dev` profile is permitted to relax these.
    pub fn is_bounded(&self) -> bool {
        self.seccomp != SeccompTier::Unrestricted && !self.egress.is_unrestricted()
    }
}

/// The production profile, and the default when `--security-profile` is unset.
/// Highest practical security: the seccomp floor that still runs a workload,
/// deny-all egress, and no snapshot. The only deployable profile.
pub const PRODUCTION: SecurityProfile = SecurityProfile {
    name: "production",
    seccomp: SeccompTier::Standard,
    egress: NetworkPreset::None,
    snapshot_allowed: false,
    deployable: true,
};

/// The development-only profile: no seccomp filter and open egress for
/// inner-loop ergonomics (debuggers, arbitrary hosts), snapshots permitted.
/// `deployable = false` — it can never reach production, which is exactly why
/// it is allowed to be loose.
pub const DEV: SecurityProfile = SecurityProfile {
    name: "dev",
    seccomp: SeccompTier::Unrestricted,
    egress: NetworkPreset::Unrestricted,
    snapshot_allowed: true,
    deployable: false,
};

/// All named profiles, production first. `ALL[0]` is the default.
pub const ALL: &[SecurityProfile] = &[PRODUCTION, DEV];

/// The default profile when `--security-profile` is unset: production.
pub fn default_security_profile() -> SecurityProfile {
    ALL[0]
}

/// Resolve a `--security-profile <name>` selection to its per-seam matrix.
/// Case-insensitive and whitespace-trimmed; `prod`/`production` and
/// `dev`/`development` are accepted. An unrecognized name fails closed with
/// the list of valid names rather than silently degrading.
pub fn resolve_security_profile(name: &str) -> Result<SecurityProfile, ProfileError> {
    let key = name.trim().to_ascii_lowercase();
    let resolved = match key.as_str() {
        "production" | "prod" => Some(PRODUCTION),
        "dev" | "development" => Some(DEV),
        _ => None,
    };
    resolved.ok_or_else(|| ProfileError {
        requested: name.to_string(),
    })
}

/// A `--security-profile` selection that named no known profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileError {
    /// What the caller asked for, verbatim.
    pub requested: String,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let valid: Vec<&str> = ALL.iter().map(|p| p.name).collect();
        write!(
            f,
            "unknown security profile {:?} (expected one of: {})",
            self.requested,
            valid.join(", ")
        )
    }
}

impl std::error::Error for ProfileError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_is_the_default_and_locks_every_seam() {
        let def = default_security_profile();
        assert_eq!(def, PRODUCTION);
        assert_eq!(def, resolve_security_profile("production").unwrap());
        assert_eq!(def.seccomp, SeccompTier::Standard);
        assert!(
            def.egress.is_deny_all(),
            "production egress must be deny-all"
        );
        assert!(!def.snapshot_allowed, "production must forbid snapshots");
        assert!(def.deployable, "production must be deployable");
    }

    #[test]
    fn dev_is_development_only_and_never_deployable() {
        let dev = resolve_security_profile("dev").unwrap();
        assert!(!dev.deployable, "dev must never be deployable");
        assert!(dev.snapshot_allowed);
    }

    #[test]
    fn every_deployable_profile_is_bounded() {
        // The contract that lets `dev` be loose: anything that can deploy must
        // keep a seccomp filter and a non-open egress. A future deployable
        // profile that relaxed a seam would trip this.
        for p in ALL {
            if p.deployable {
                assert!(
                    p.is_bounded(),
                    "deployable profile {} must keep a seccomp filter and bounded egress",
                    p.name
                );
            }
        }
    }

    #[test]
    fn exactly_one_profile_is_deployable_and_it_is_the_default() {
        let deployable: Vec<_> = ALL.iter().filter(|p| p.deployable).collect();
        assert_eq!(
            deployable.len(),
            1,
            "production is the sole deployable profile"
        );
        assert_eq!(deployable[0], &default_security_profile());
    }

    #[test]
    fn resolve_accepts_aliases_and_is_case_insensitive() {
        assert_eq!(resolve_security_profile("  Prod ").unwrap(), PRODUCTION);
        assert_eq!(resolve_security_profile("PRODUCTION").unwrap(), PRODUCTION);
        assert_eq!(resolve_security_profile("development").unwrap(), DEV);
        assert_eq!(resolve_security_profile("DEV").unwrap(), DEV);
    }

    #[test]
    fn unknown_profile_fails_closed_and_lists_valid_names() {
        let err = resolve_security_profile("yolo").unwrap_err();
        assert_eq!(err.requested, "yolo");
        let msg = err.to_string();
        assert!(msg.contains("production"), "{msg}");
        assert!(msg.contains("dev"), "{msg}");
    }
}
