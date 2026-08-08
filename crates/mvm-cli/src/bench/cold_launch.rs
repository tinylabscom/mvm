//! Prepared cold-launch measurement: the lane a sample was measured in, the
//! host/artifact context it was measured under, the gate that refuses a
//! contaminated sample, and the p50/p95/p99 report built from a set of them.
//!
//! The launch itself is measured by the `mvmctl` process under test, which
//! writes a [`LaunchSample`]. The rules here are pure, so every one of them
//! is unit-tested without booting a guest.
//!
//! Both halves of the launch-measurement schema are named here — the
//! [`LaunchSubMarks`]/[`SubPhase`] producer as well as the sample and report
//! it feeds — so a reader adding a phase finds the mark, the wire field, and
//! the percentile column in one place rather than three.

use serde::{Deserialize, Serialize};

pub use crate::commands::vm::launch_sample::{
    ArtifactPaths, BuildProfile, GuestSizing, LAUNCH_SAMPLE_SCHEMA_VERSION, LaunchSample,
    LaunchSubTimings, LaunchWork,
};
pub use crate::commands::vm::phase_timing::{
    LaunchMode, LaunchSubMarks, RunPhaseTimings, SubPhase,
};

use super::stats::percentile;

/// Report schema version for [`ColdLaunchReport`].
pub const COLD_LAUNCH_SCHEMA_VERSION: u32 = 1;

/// The measurement lanes the cold-launch contract reports independently.
///
/// They are reported separately rather than averaged because they measure
/// different things: folding a first-time image acquisition into a prepared
/// launch number would make the prepared number meaningless and hide the
/// acquisition cost at the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchLane {
    /// Cached artifacts, no mount image, new VMM and new guest identity.
    PreparedCold,
    /// The same launch with an unchanged cached read-only mount image.
    PreparedColdMountHit,
    /// Directory fingerprint plus first mount-image materialization.
    MountMiss,
    /// Image acquisition, unpack, verification, and preparation.
    ArtifactMiss,
    /// A claimed warm standby — kept as a comparison, never folded into a
    /// cold number.
    WarmClaim,
}

impl LaunchLane {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreparedCold => "prepared_cold",
            Self::PreparedColdMountHit => "prepared_cold_mount_hit",
            Self::MountMiss => "mount_miss",
            Self::ArtifactMiss => "artifact_miss",
            Self::WarmClaim => "warm_claim",
        }
    }
}

/// Why a sample does not belong in the lane it was labeled with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneViolation {
    /// The sample came from an unoptimised binary.
    NotReleaseBuild { profile: BuildProfile },
    /// The sample's schema is not the one this consumer understands.
    SchemaMismatch { found: u32, expected: u32 },
    /// The launch performed work the lane forbids.
    ForbiddenWork {
        lane: LaunchLane,
        performed: Vec<&'static str>,
    },
    /// The launch took a path the lane requires it not to take, or did not
    /// take the one it requires.
    WrongLaunchMode { lane: LaunchLane, found: LaunchMode },
    /// The lane requires the work to have happened and it did not.
    MissingWork {
        lane: LaunchLane,
        expected: &'static str,
    },
}

impl std::fmt::Display for LaneViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReleaseBuild { profile } => write!(
                f,
                "launch sample came from a {} build; a launch measurement is release-only",
                profile.as_str()
            ),
            Self::SchemaMismatch { found, expected } => write!(
                f,
                "launch sample schema {found} is not the expected {expected}"
            ),
            Self::ForbiddenWork { lane, performed } => write!(
                f,
                "lane {} forbids {} but the launch performed it",
                lane.as_str(),
                performed.join(", ")
            ),
            Self::WrongLaunchMode { lane, found } => write!(
                f,
                "lane {} cannot be measured from a {} launch",
                lane.as_str(),
                found.as_str()
            ),
            Self::MissingWork { lane, expected } => write!(
                f,
                "lane {} requires {expected} and the launch did not perform it",
                lane.as_str()
            ),
        }
    }
}

impl std::error::Error for LaneViolation {}

/// Accept `sample` as a measurement of `lane`, or say why it is not one.
///
/// The prepared-cold lanes are the reason this exists: a launch that quietly
/// pulled an image, ran a build, materialized a mount image, or claimed a
/// warm standby is not a prepared cold launch, and reporting it as one would
/// make the number unfalsifiable. The gate reads [`LaunchWork`] flags rather
/// than timings — an uninstrumented phase records no span, and refusing on a
/// missing span would pass exactly the contamination it exists to catch.
pub fn validate_lane(lane: LaunchLane, sample: &LaunchSample) -> Result<(), LaneViolation> {
    if sample.schema_version != LAUNCH_SAMPLE_SCHEMA_VERSION {
        return Err(LaneViolation::SchemaMismatch {
            found: sample.schema_version,
            expected: LAUNCH_SAMPLE_SCHEMA_VERSION,
        });
    }
    if sample.build_profile != BuildProfile::Release {
        return Err(LaneViolation::NotReleaseBuild {
            profile: sample.build_profile,
        });
    }
    let work = sample.work;
    let forbid = |names: Vec<&'static str>| -> Result<(), LaneViolation> {
        let performed: Vec<&'static str> = work
            .performed()
            .into_iter()
            .filter(|name| names.contains(name))
            .collect();
        if performed.is_empty() {
            Ok(())
        } else {
            Err(LaneViolation::ForbiddenWork { lane, performed })
        }
    };

    match lane {
        LaunchLane::PreparedCold => {
            forbid(vec![
                "image_pull",
                "image_build",
                "mount_materialize",
                "warm_claim",
            ])?;
            require_cold(lane, sample)
        }
        LaunchLane::PreparedColdMountHit => {
            forbid(vec![
                "image_pull",
                "image_build",
                "mount_materialize",
                "warm_claim",
            ])?;
            require_cold(lane, sample)
        }
        LaunchLane::MountMiss => {
            forbid(vec!["image_pull", "image_build", "warm_claim"])?;
            if !work.mount_materialize {
                return Err(LaneViolation::MissingWork {
                    lane,
                    expected: "mount_materialize",
                });
            }
            require_cold(lane, sample)
        }
        LaunchLane::ArtifactMiss => {
            forbid(vec!["warm_claim"])?;
            if !(work.image_pull || work.image_build) {
                return Err(LaneViolation::MissingWork {
                    lane,
                    expected: "image_pull or image_build",
                });
            }
            require_cold(lane, sample)
        }
        LaunchLane::WarmClaim => {
            if !work.warm_claim || sample.launch_mode != LaunchMode::Warm {
                return Err(LaneViolation::MissingWork {
                    lane,
                    expected: "warm_claim",
                });
            }
            Ok(())
        }
    }
}

/// Every cold lane requires a genuinely new VMM and guest identity. A warm
/// claim reaching a cold lane is the failure this catches even when the work
/// flag was not set — the two signals are independent on purpose.
fn require_cold(lane: LaunchLane, sample: &LaunchSample) -> Result<(), LaneViolation> {
    if sample.launch_mode == LaunchMode::Cold {
        Ok(())
    } else {
        Err(LaneViolation::WrongLaunchMode {
            lane,
            found: sample.launch_mode,
        })
    }
}

/// Digests of the artifacts a lane was measured against, resolved outside the
/// timed window so hashing never lands in a launch sample.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArtifactDigests {
    pub kernel_sha256: Option<String>,
    pub initramfs_sha256: Option<String>,
    pub runtime_overlay_sha256: Option<String>,
    pub rootfs_sha256: Option<String>,
}

/// Which caches a lane was measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountCacheState {
    /// The launch declared no mount.
    NotUsed,
    /// A cached mount image was attached.
    Hit,
    /// A mount image was materialized.
    Miss,
}

/// Cache posture derived from what the launch actually did, never asserted by
/// the operator: a hand-declared "warm cache" that is wrong turns a cold
/// number into a fiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheState {
    /// No acquisition ran, so every artifact came from a local cache.
    pub artifacts_cached: bool,
    pub mount: MountCacheState,
}

impl CacheState {
    /// Derive the posture from a launch's own work flags and mount spans.
    #[must_use]
    pub fn from_sample(sample: &LaunchSample) -> Self {
        let mount = if sample.work.mount_materialize {
            MountCacheState::Miss
        } else if sample.sub_phases.mount_cache_lookup_ms.is_some() {
            MountCacheState::Hit
        } else {
            MountCacheState::NotUsed
        };
        Self {
            artifacts_cached: !(sample.work.image_pull || sample.work.image_build),
            mount,
        }
    }
}

/// Host and configuration fingerprint a lane was measured under. Two reports
/// are comparable only when these match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchContext {
    pub backend: String,
    pub os: String,
    pub arch: String,
    pub mvm_version: String,
    /// The VMM's own version where it is knowable without probing a foreign
    /// binary. `None` is "not resolved", never "unversioned".
    pub vmm_version: Option<String>,
    pub sizing: GuestSizing,
    pub filesystem: Option<String>,
    pub artifacts: ArtifactPaths,
    pub digests: ArtifactDigests,
}

/// One measured launch, with everything needed to re-read it later.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdLaunchSample {
    pub lane: LaunchLane,
    /// 1-based index within the lane's measured set. Warm-up iterations are
    /// discarded before numbering, so sample 1 is the first measured launch.
    pub number: u32,
    pub context: LaunchContext,
    pub cache: CacheState,
    pub work: LaunchWork,
    pub launch_mode: LaunchMode,
    pub phases: RunPhaseTimings,
    pub sub_phases: LaunchSubTimings,
}

/// Percentile summary for one span across a lane's samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpanStats {
    /// How many samples carried this span. A sub-phase no launch recorded is
    /// reported with `samples: 0` rather than omitted, so a reader can tell
    /// "never measured" from "measured as fast".
    pub samples: u32,
    /// `None` exactly when `samples` is zero. A percentile over nothing is
    /// not a number, and a number is what a JSON reader would take it for.
    pub p50: Option<f64>,
    pub p95: Option<f64>,
    pub p99: Option<f64>,
}

impl SpanStats {
    #[must_use]
    pub fn from_samples(samples: &[f64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        Self {
            samples: u32::try_from(samples.len()).unwrap_or(u32::MAX),
            p50: Some(percentile(samples, 50.0)),
            p95: Some(percentile(samples, 95.0)),
            p99: Some(percentile(samples, 99.0)),
        }
    }
}

/// Percentiles for every span of one lane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneStats {
    /// Admitted plan to command dispatch — the window the launch contract is
    /// set against.
    pub dispatch_window_ms: SpanStats,
    pub total_ms: SpanStats,
    pub resolve_ms: SpanStats,
    pub drives_ms: SpanStats,
    pub admit_ms: SpanStats,
    pub backend_start_ms: SpanStats,
    pub vsock_wait_ms: SpanStats,
    pub command_ms: SpanStats,
    pub teardown_ms: SpanStats,
    /// One entry per sub-phase, in declaration order.
    pub sub_phases: Vec<(String, SpanStats)>,
}

/// A lane's full result: raw samples first, percentiles derived from them.
///
/// The raw vector is not optional. Summary-only evidence cannot be
/// re-analysed, cannot show a bimodal distribution, and cannot be checked
/// against the percentiles that were published from it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdLaunchReport {
    pub schema_version: u32,
    pub lane: LaunchLane,
    pub warmup: u32,
    pub stats: LaneStats,
    pub raw: Vec<ColdLaunchSample>,
}

/// Every sub-phase name a report summarises, in the order they occur.
const SUB_PHASE_NAMES: [&str; 9] = [
    "mount_fingerprint",
    "mount_cache_lookup",
    "mount_materialize",
    "artifact_verify",
    "vmm_create",
    "guest_kernel_entry",
    "agent_auth",
    "first_dispatch",
    "cleanup_handoff",
];

/// Build a lane report from its measured samples.
#[must_use]
pub fn build_cold_launch_report(
    lane: LaunchLane,
    warmup: u32,
    raw: Vec<ColdLaunchSample>,
) -> ColdLaunchReport {
    let col = |f: fn(&ColdLaunchSample) -> f64| {
        SpanStats::from_samples(&raw.iter().map(f).collect::<Vec<f64>>())
    };
    let sub = |name: &str| {
        let values: Vec<f64> = raw
            .iter()
            .filter_map(|sample| {
                sample
                    .sub_phases
                    .recorded()
                    .into_iter()
                    .find(|(recorded, _)| *recorded == name)
                    .map(|(_, ms)| ms)
            })
            .collect();
        SpanStats::from_samples(&values)
    };
    ColdLaunchReport {
        schema_version: COLD_LAUNCH_SCHEMA_VERSION,
        lane,
        warmup,
        stats: LaneStats {
            dispatch_window_ms: col(|s| s.phases.dispatch_window_ms()),
            total_ms: col(|s| s.phases.total_ms),
            resolve_ms: col(|s| s.phases.resolve_ms),
            drives_ms: col(|s| s.phases.drives_ms),
            admit_ms: col(|s| s.phases.admit_ms),
            backend_start_ms: col(|s| s.phases.backend_start_ms),
            vsock_wait_ms: col(|s| s.phases.vsock_wait_ms),
            command_ms: col(|s| s.phases.command_ms),
            teardown_ms: col(|s| s.phases.teardown_ms),
            sub_phases: SUB_PHASE_NAMES
                .iter()
                .map(|name| ((*name).to_string(), sub(name)))
                .collect(),
        },
        raw,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phases(total_ms: f64) -> RunPhaseTimings {
        RunPhaseTimings {
            launch_mode: LaunchMode::Cold,
            resolve_ms: 1.0,
            drives_ms: 2.0,
            admit_ms: 3.0,
            pool_wait_ms: 0.0,
            claim_ms: 0.0,
            backend_start_ms: 100.0,
            vsock_wait_ms: 30.0,
            warm_window_ms: 130.0,
            command_ms: 5.0,
            teardown_ms: 7.0,
            total_ms,
        }
    }

    fn launch_sample() -> LaunchSample {
        LaunchSample {
            schema_version: LAUNCH_SAMPLE_SCHEMA_VERSION,
            build_profile: BuildProfile::Release,
            mvm_version: "0.1.0".to_string(),
            backend: "hvf".to_string(),
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            launch_mode: LaunchMode::Cold,
            sizing: GuestSizing {
                cpus: 2,
                memory_mib: 512,
                mem_initial_mib: None,
            },
            artifacts: ArtifactPaths::default(),
            work: LaunchWork::default(),
            phases: phases(148.0),
            sub_phases: LaunchSubTimings::default(),
        }
    }

    fn cold_sample(number: u32, total_ms: f64) -> ColdLaunchSample {
        ColdLaunchSample {
            lane: LaunchLane::PreparedCold,
            number,
            context: LaunchContext {
                backend: "hvf".to_string(),
                os: "macos".to_string(),
                arch: "aarch64".to_string(),
                mvm_version: "0.1.0".to_string(),
                vmm_version: Some("0.1.0".to_string()),
                sizing: GuestSizing {
                    cpus: 2,
                    memory_mib: 512,
                    mem_initial_mib: None,
                },
                filesystem: Some("apfs".to_string()),
                artifacts: ArtifactPaths::default(),
                digests: ArtifactDigests::default(),
            },
            cache: CacheState {
                artifacts_cached: true,
                mount: MountCacheState::NotUsed,
            },
            work: LaunchWork::default(),
            launch_mode: LaunchMode::Cold,
            phases: phases(total_ms),
            sub_phases: LaunchSubTimings {
                vmm_create_ms: Some(total_ms / 2.0),
                ..LaunchSubTimings::default()
            },
        }
    }

    #[test]
    fn prepared_cold_accepts_a_clean_release_sample() {
        assert_eq!(
            validate_lane(LaunchLane::PreparedCold, &launch_sample()),
            Ok(())
        );
    }

    #[test]
    fn prepared_cold_rejects_an_image_pull() {
        let mut sample = launch_sample();
        sample.work.image_pull = true;
        let err = validate_lane(LaunchLane::PreparedCold, &sample).unwrap_err();
        assert_eq!(
            err,
            LaneViolation::ForbiddenWork {
                lane: LaunchLane::PreparedCold,
                performed: vec!["image_pull"],
            }
        );
        assert!(err.to_string().contains("image_pull"));
    }

    #[test]
    fn prepared_cold_rejects_a_build() {
        let mut sample = launch_sample();
        sample.work.image_build = true;
        assert!(matches!(
            validate_lane(LaunchLane::PreparedCold, &sample),
            Err(LaneViolation::ForbiddenWork { .. })
        ));
    }

    #[test]
    fn prepared_cold_rejects_mount_materialization() {
        let mut sample = launch_sample();
        sample.work.mount_materialize = true;
        sample.sub_phases.mount_materialize_ms = Some(429_809.0);
        let err = validate_lane(LaunchLane::PreparedCold, &sample).unwrap_err();
        assert_eq!(
            err,
            LaneViolation::ForbiddenWork {
                lane: LaunchLane::PreparedCold,
                performed: vec!["mount_materialize"],
            }
        );
    }

    #[test]
    fn prepared_cold_rejects_a_warm_claim_by_flag_and_by_mode() {
        let mut by_flag = launch_sample();
        by_flag.work.warm_claim = true;
        assert!(matches!(
            validate_lane(LaunchLane::PreparedCold, &by_flag),
            Err(LaneViolation::ForbiddenWork { .. })
        ));

        // A warm launch whose work flag was never set must still be refused:
        // the two signals are independent so one going missing cannot let a
        // warm claim pass as a cold launch.
        let mut by_mode = launch_sample();
        by_mode.launch_mode = LaunchMode::Warm;
        assert_eq!(
            validate_lane(LaunchLane::PreparedCold, &by_mode),
            Err(LaneViolation::WrongLaunchMode {
                lane: LaunchLane::PreparedCold,
                found: LaunchMode::Warm,
            })
        );
    }

    #[test]
    fn prepared_cold_reports_every_contaminating_kind() {
        let mut sample = launch_sample();
        sample.work = LaunchWork {
            image_pull: true,
            image_build: true,
            mount_materialize: true,
            warm_claim: true,
        };
        let err = validate_lane(LaunchLane::PreparedCold, &sample).unwrap_err();
        assert_eq!(
            err,
            LaneViolation::ForbiddenWork {
                lane: LaunchLane::PreparedCold,
                performed: vec![
                    "image_pull",
                    "image_build",
                    "mount_materialize",
                    "warm_claim"
                ],
            }
        );
    }

    #[test]
    fn mount_hit_lane_has_the_same_prepared_bar() {
        let mut sample = launch_sample();
        sample.sub_phases.mount_cache_lookup_ms = Some(0.8);
        assert_eq!(
            validate_lane(LaunchLane::PreparedColdMountHit, &sample),
            Ok(())
        );

        sample.work.mount_materialize = true;
        assert!(matches!(
            validate_lane(LaunchLane::PreparedColdMountHit, &sample),
            Err(LaneViolation::ForbiddenWork { .. })
        ));
    }

    #[test]
    fn mount_miss_lane_requires_materialization() {
        let mut sample = launch_sample();
        assert_eq!(
            validate_lane(LaunchLane::MountMiss, &sample),
            Err(LaneViolation::MissingWork {
                lane: LaunchLane::MountMiss,
                expected: "mount_materialize",
            })
        );
        sample.work.mount_materialize = true;
        assert_eq!(validate_lane(LaunchLane::MountMiss, &sample), Ok(()));

        // Acquisition still belongs to the artifact-miss lane.
        sample.work.image_pull = true;
        assert!(matches!(
            validate_lane(LaunchLane::MountMiss, &sample),
            Err(LaneViolation::ForbiddenWork { .. })
        ));
    }

    #[test]
    fn artifact_miss_lane_requires_acquisition() {
        let mut sample = launch_sample();
        assert_eq!(
            validate_lane(LaunchLane::ArtifactMiss, &sample),
            Err(LaneViolation::MissingWork {
                lane: LaunchLane::ArtifactMiss,
                expected: "image_pull or image_build",
            })
        );
        sample.work.image_build = true;
        assert_eq!(validate_lane(LaunchLane::ArtifactMiss, &sample), Ok(()));
    }

    #[test]
    fn warm_lane_requires_a_warm_claim() {
        let mut sample = launch_sample();
        assert!(matches!(
            validate_lane(LaunchLane::WarmClaim, &sample),
            Err(LaneViolation::MissingWork { .. })
        ));
        sample.work.warm_claim = true;
        sample.launch_mode = LaunchMode::Warm;
        assert_eq!(validate_lane(LaunchLane::WarmClaim, &sample), Ok(()));
    }

    #[test]
    fn every_lane_refuses_a_debug_build() {
        let mut sample = launch_sample();
        sample.build_profile = BuildProfile::Debug;
        sample.work.warm_claim = true;
        sample.launch_mode = LaunchMode::Warm;
        for lane in [
            LaunchLane::PreparedCold,
            LaunchLane::PreparedColdMountHit,
            LaunchLane::MountMiss,
            LaunchLane::ArtifactMiss,
            LaunchLane::WarmClaim,
        ] {
            assert_eq!(
                validate_lane(lane, &sample),
                Err(LaneViolation::NotReleaseBuild {
                    profile: BuildProfile::Debug
                }),
                "lane {} must refuse a debug sample",
                lane.as_str()
            );
        }
    }

    #[test]
    fn a_foreign_schema_is_refused_before_anything_else() {
        let mut sample = launch_sample();
        sample.schema_version = LAUNCH_SAMPLE_SCHEMA_VERSION + 1;
        sample.build_profile = BuildProfile::Debug;
        assert_eq!(
            validate_lane(LaunchLane::PreparedCold, &sample),
            Err(LaneViolation::SchemaMismatch {
                found: LAUNCH_SAMPLE_SCHEMA_VERSION + 1,
                expected: LAUNCH_SAMPLE_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn cache_state_is_derived_from_what_the_launch_did() {
        let mut sample = launch_sample();
        assert_eq!(
            CacheState::from_sample(&sample),
            CacheState {
                artifacts_cached: true,
                mount: MountCacheState::NotUsed
            }
        );

        sample.sub_phases.mount_cache_lookup_ms = Some(0.5);
        assert_eq!(CacheState::from_sample(&sample).mount, MountCacheState::Hit);

        sample.work.mount_materialize = true;
        assert_eq!(
            CacheState::from_sample(&sample).mount,
            MountCacheState::Miss
        );

        sample.work.image_pull = true;
        assert!(!CacheState::from_sample(&sample).artifacts_cached);
    }

    #[test]
    fn report_keeps_raw_samples_and_derives_percentiles() {
        let raw: Vec<ColdLaunchSample> = (1..=4)
            .map(|i| cold_sample(i, f64::from(i) * 100.0))
            .collect();
        let report = build_cold_launch_report(LaunchLane::PreparedCold, 2, raw);

        assert_eq!(report.schema_version, COLD_LAUNCH_SCHEMA_VERSION);
        assert_eq!(report.warmup, 2);
        assert_eq!(report.raw.len(), 4);
        assert_eq!(report.stats.total_ms.samples, 4);
        assert_eq!(report.stats.total_ms.p50, Some(250.0));
        assert_eq!(report.stats.total_ms.p95, Some(385.0));
        assert_eq!(report.stats.total_ms.p99, Some(397.0));
        // Dispatch window is constant across the fixture, so every
        // percentile lands on it.
        assert_eq!(report.stats.dispatch_window_ms.p50, Some(130.0));
        assert_eq!(report.stats.dispatch_window_ms.p99, Some(130.0));
    }

    #[test]
    fn report_summarises_only_the_sub_phases_that_were_recorded() {
        let raw: Vec<ColdLaunchSample> = (1..=2)
            .map(|i| cold_sample(i, f64::from(i) * 100.0))
            .collect();
        let report = build_cold_launch_report(LaunchLane::PreparedCold, 0, raw);

        let by_name = |name: &str| {
            report
                .stats
                .sub_phases
                .iter()
                .find(|(recorded, _)| recorded == name)
                .map(|(_, stats)| *stats)
                .expect("every sub-phase is reported")
        };
        assert_eq!(report.stats.sub_phases.len(), SUB_PHASE_NAMES.len());
        assert_eq!(by_name("vmm_create").samples, 2);
        assert_eq!(by_name("vmm_create").p50, Some(75.0));
        // A sub-phase no launch recorded is reported as measured zero times,
        // not as a zero-millisecond span.
        assert_eq!(by_name("mount_materialize").samples, 0);
        assert_eq!(by_name("mount_materialize").p50, None);
    }

    #[test]
    fn report_roundtrips_through_json() {
        let report =
            build_cold_launch_report(LaunchLane::PreparedCold, 2, vec![cold_sample(1, 90.0)]);
        let json = serde_json::to_string(&report).unwrap();
        let back: ColdLaunchReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn lane_names_are_stable() {
        assert_eq!(LaunchLane::PreparedCold.as_str(), "prepared_cold");
        assert_eq!(
            LaunchLane::PreparedColdMountHit.as_str(),
            "prepared_cold_mount_hit"
        );
        assert_eq!(LaunchLane::MountMiss.as_str(), "mount_miss");
        assert_eq!(LaunchLane::ArtifactMiss.as_str(), "artifact_miss");
        assert_eq!(LaunchLane::WarmClaim.as_str(), "warm_claim");
    }
}
