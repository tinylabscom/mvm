//! Kernel-pin staleness assessment — the pure core of the kernel security
//! watcher.
//!
//! mvm pins the guest kernel in two places (the nixpkgs `linux_6_12` package
//! and the libkrunfw tarball). The LTS maintainer backports security fixes
//! into point releases, so "our pin trails the latest published point release
//! of its series" is a high-signal, deterministic proxy for "missing security
//! fixes" — no CVE database required (that enrichment is a later phase).
//!
//! This module has no I/O: it takes the local pins and a snapshot of upstream
//! releases and returns a [`KernelAdvisory`]. The fetch + emit lives in the
//! `xtask` shell, so the comparison logic stays trivially unit-testable and
//! the "should we remediate?" decision is enforced in one place.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One kernel pin mvm carries (e.g. the nixpkgs kernel, the libkrunfw tarball).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelPin {
    /// Stable identifier for the pin's source (for the advisory + messages).
    pub name: String,
    /// `MAJOR.MINOR.PATCH` version string.
    pub version: String,
}

/// Latest published point release per `MAJOR.MINOR` series, as fetched from
/// upstream (kernel.org). A series absent here yields [`Staleness::Unknown`]
/// — never a false "up to date".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamReleases {
    pub latest_by_series: BTreeMap<String, String>,
}

/// How a single pin compares to upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Staleness {
    /// Pin is at (or ahead of) the latest known point release.
    UpToDate,
    /// Pin trails the latest point release by `patch_gap` releases.
    Behind {
        current: String,
        latest: String,
        patch_gap: u32,
    },
    /// Couldn't decide — unparsable version or no upstream data. Never
    /// triggers remediation (fail-open on knowledge, not on action).
    Unknown { reason: String },
}

/// The watcher's verdict across all pins.
///
/// This is a **stable JSON wire contract** — the fleet orchestrator (mvmd)
/// polls it to decide whether to remediate. The consumer flow: poll the
/// advisory (from the watch workflow's artifact or by running the xtask); if
/// `action_recommended`, bump the pin(s), rebuild the kernel, then
/// `mvmctl vm rekernel` each fleet member (the single-VM remediation
/// primitive). `deny_unknown_fields` + the schema-stability test keep this
/// shape from drifting under consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelAdvisory {
    /// Per-pin assessment.
    pub pins: Vec<(KernelPin, Staleness)>,
    /// The most-stale pin's status — the headline.
    pub worst: Staleness,
    /// Whether a pin trails far enough to warrant a kernel bump + rekernel.
    /// Only [`Staleness::Behind`] sets this; `Unknown` never does.
    pub action_recommended: bool,
}

/// Minimum patch gap that recommends remediation. A single missed point
/// release on an LTS line is already security-relevant.
const ACTION_THRESHOLD: u32 = 1;

/// Assess every pin against upstream. Pure — no I/O.
pub fn assess(pins: &[KernelPin], upstream: &UpstreamReleases) -> KernelAdvisory {
    let assessed: Vec<(KernelPin, Staleness)> = pins
        .iter()
        .map(|p| (p.clone(), assess_one(p, upstream)))
        .collect();

    let worst = assessed
        .iter()
        .map(|(_, s)| s)
        .max_by_key(|s| severity(s))
        .cloned()
        .unwrap_or(Staleness::UpToDate);

    let action_recommended = assessed.iter().any(
        |(_, s)| matches!(s, Staleness::Behind { patch_gap, .. } if *patch_gap >= ACTION_THRESHOLD),
    );

    KernelAdvisory {
        pins: assessed,
        worst,
        action_recommended,
    }
}

/// Severity ordering for picking the worst pin: `Behind` (by gap) > `Unknown`
/// > `UpToDate`. `Behind` is always ranked above `Unknown` regardless of gap.
fn severity(s: &Staleness) -> u32 {
    match s {
        Staleness::UpToDate => 0,
        Staleness::Unknown { .. } => 1,
        Staleness::Behind { patch_gap, .. } => 1_000 + patch_gap,
    }
}

fn assess_one(pin: &KernelPin, upstream: &UpstreamReleases) -> Staleness {
    let Some((series, patch)) = parse_version(&pin.version) else {
        return Staleness::Unknown {
            reason: format!("unparsable pin version '{}'", pin.version),
        };
    };
    let Some(latest) = upstream.latest_by_series.get(&series) else {
        return Staleness::Unknown {
            reason: format!("no upstream release data for series {series}"),
        };
    };
    let Some((_, latest_patch)) = parse_version(latest) else {
        return Staleness::Unknown {
            reason: format!("unparsable upstream version '{latest}'"),
        };
    };
    if latest_patch > patch {
        Staleness::Behind {
            current: pin.version.clone(),
            latest: latest.clone(),
            patch_gap: latest_patch - patch,
        }
    } else {
        Staleness::UpToDate
    }
}

/// Parse `MAJOR.MINOR.PATCH` → (`"MAJOR.MINOR"` series, PATCH). Trailing
/// `.PATCH` extras are ignored; a non-numeric component fails the parse.
fn parse_version(v: &str) -> Option<(String, u32)> {
    let mut parts = v.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    let patch: u32 = parts.next()?.parse().ok()?;
    Some((format!("{major}.{minor}"), patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream(pairs: &[(&str, &str)]) -> UpstreamReleases {
        UpstreamReleases {
            latest_by_series: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn pin(version: &str) -> KernelPin {
        KernelPin {
            name: "k".into(),
            version: version.into(),
        }
    }

    #[test]
    fn behind_when_pin_trails_point_release() {
        let a = assess(&[pin("6.12.87")], &upstream(&[("6.12", "6.12.95")]));
        assert!(matches!(a.worst, Staleness::Behind { patch_gap: 8, .. }));
        assert!(a.action_recommended);
    }

    #[test]
    fn up_to_date_when_pin_is_latest() {
        let a = assess(&[pin("6.12.95")], &upstream(&[("6.12", "6.12.95")]));
        assert!(matches!(a.worst, Staleness::UpToDate));
        assert!(!a.action_recommended);
    }

    #[test]
    fn unknown_when_series_absent_never_recommends_action() {
        let a = assess(&[pin("6.12.87")], &upstream(&[]));
        assert!(matches!(a.worst, Staleness::Unknown { .. }));
        assert!(!a.action_recommended);
    }

    #[test]
    fn unknown_on_unparsable_pin() {
        let a = assess(&[pin("not-a-version")], &upstream(&[("6.12", "6.12.95")]));
        assert!(matches!(a.worst, Staleness::Unknown { .. }));
        assert!(!a.action_recommended);
    }

    #[test]
    fn worst_picks_the_most_behind_pin() {
        let pins = [
            KernelPin {
                name: "a".into(),
                version: "6.12.94".into(),
            },
            KernelPin {
                name: "b".into(),
                version: "6.12.80".into(),
            },
        ];
        let a = assess(&pins, &upstream(&[("6.12", "6.12.95")]));
        // b is 15 behind, a is 1 behind → worst = b's gap.
        assert!(matches!(a.worst, Staleness::Behind { patch_gap: 15, .. }));
        assert!(a.action_recommended);
    }

    #[test]
    fn behind_outranks_unknown_in_worst() {
        let pins = [
            KernelPin {
                name: "known".into(),
                version: "6.12.90".into(),
            },
            KernelPin {
                name: "mystery".into(),
                version: "5.15.1".into(),
            }, // no series data
        ];
        let a = assess(&pins, &upstream(&[("6.12", "6.12.95")]));
        assert!(matches!(a.worst, Staleness::Behind { .. }));
    }

    #[test]
    fn advisory_serde_roundtrip() {
        let a = assess(&[pin("6.12.87")], &upstream(&[("6.12", "6.12.95")]));
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(serde_json::from_str::<KernelAdvisory>(&j).unwrap(), a);
    }

    /// Schema-stability guard: the JSON shape is the contract mvmd polls.
    /// Renaming a field here breaks this test — a deliberate tripwire so a
    /// contract change is a conscious decision, not an accident.
    #[test]
    fn advisory_json_schema_is_stable() {
        let a = assess(&[pin("6.12.87")], &upstream(&[("6.12", "6.12.95")]));
        let v = serde_json::to_value(&a).unwrap();

        assert!(v.get("pins").unwrap().is_array());
        assert!(v.get("action_recommended").unwrap().is_boolean());

        // `worst` is a tagged Staleness: `{ "status": "behind", current, latest, patch_gap }`.
        let worst = v.get("worst").unwrap();
        assert_eq!(worst.get("status").unwrap(), "behind");
        assert!(worst.get("current").unwrap().is_string());
        assert!(worst.get("latest").unwrap().is_string());
        assert!(worst.get("patch_gap").unwrap().is_number());

        // Each pin entry is `[KernelPin, Staleness]`.
        let entry = &v.get("pins").unwrap().as_array().unwrap()[0];
        let pin = &entry.as_array().unwrap()[0];
        assert!(pin.get("name").unwrap().is_string());
        assert!(pin.get("version").unwrap().is_string());
        assert!(entry.as_array().unwrap()[1].get("status").is_some());
    }
}
