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
    ArtifactPaths, BuildProfile, GuestSizing, LAUNCH_SAMPLE_SCHEMA_VERSION, LaunchRootStrategy,
    LaunchSample, LaunchSubTimings, LaunchWork, ProcessMemoryDelta, ProcessMemorySnapshot,
    WarmFirstCommandMemory,
};
pub use crate::commands::vm::phase_timing::{
    LaunchMode, LaunchSubMarks, RunPhaseTimings, SubPhase,
};
pub use mvm_core::launch_trace::TracePhase;

use super::stats::percentile;

/// Report schema version for [`ColdLaunchReport`]. Version 2 added artifact
/// byte measurements and optional resolved kernel-config evidence; version 3
/// adds the selected root filesystem strategy; version 4 adds whole-VMM warm
/// resident-memory and first-command fault evidence; version 5 changes Linux
/// memory accounting from PSS to RSS; version 6 adds maxima and the explicit
/// hard boot requirement; version 7 adds the outer, shell-visible command
/// lifecycle wall clock. Older reports remain readable through serde defaults
/// but are not comparable without the new substrate.
pub const COLD_LAUNCH_SCHEMA_VERSION: u32 = 7;

/// Minimum measured samples in a publishable live matrix lane.
pub const MIN_MATRIX_SAMPLES: u32 = 20;

/// Required discarded warm-up launches before a publishable live matrix lane.
pub const MATRIX_WARMUP_SAMPLES: u32 = 2;

/// Prepared-cold dispatch-window p50 budget, in milliseconds.
pub const PREPARED_COLD_P50_BUDGET_MS: f64 = 200.0;

/// Prepared-cold dispatch-window p95 budget, in milliseconds.
pub const PREPARED_COLD_P95_BUDGET_MS: f64 = 250.0;

/// Prepared-cold dispatch-window p99 budget, in milliseconds.
pub const PREPARED_COLD_P99_BUDGET_MS: f64 = 300.0;

/// Every prepared cold dispatch must finish strictly below this ceiling.
///
/// Unlike the percentile budgets, this is a per-sample invariant: one launch
/// at exactly 200 ms is a failure even when every published percentile passes.
pub const PREPARED_COLD_HARD_MAX_MS: f64 = 200.0;

/// Warm-claim dispatch-window p50 budget, in milliseconds.
pub const WARM_CLAIM_P50_BUDGET_MS: f64 = 30.0;

/// Warm-claim dispatch-window p99 budget, in milliseconds.
pub const WARM_CLAIM_P99_BUDGET_MS: f64 = 50.0;

/// The dispatch-window budgets one lane publishes, by percentile.
///
/// `None` is "this lane deliberately publishes no budget at this percentile",
/// never "zero". The acquisition lanes measure work whose cost is dominated by
/// a registry and a disk, so holding them to a latency ceiling would gate mvm
/// on someone else's network.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LaneBudgets {
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
    /// Strict per-sample ceiling. A value equal to this limit fails.
    pub hard_max_ms: Option<f64>,
}

impl LaneBudgets {
    /// The published budgets in contract order, paired with the percentile
    /// label the violation and the doc table both use.
    #[must_use]
    pub const fn by_percentile(self) -> [(&'static str, Option<f64>); 3] {
        [
            ("p50", self.p50_ms),
            ("p95", self.p95_ms),
            ("p99", self.p99_ms),
        ]
    }
}

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
    /// Every lane, in contract order.
    pub const ALL: [Self; 5] = [
        Self::PreparedCold,
        Self::PreparedColdMountHit,
        Self::MountMiss,
        Self::ArtifactMiss,
        Self::WarmClaim,
    ];

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

    /// What this lane measures, in one sentence, for a reader who has not read
    /// the enum. The published table and the gate name the same thing because
    /// they read the same string.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::PreparedCold => {
                "Cached artifacts, no mount image, new VMM and new guest identity."
            }
            Self::PreparedColdMountHit => {
                "The same launch with an unchanged cached read-only mount image."
            }
            Self::MountMiss => "Directory fingerprint plus first mount-image materialization.",
            Self::ArtifactMiss => "Image acquisition, unpack, verification, and preparation.",
            Self::WarmClaim => {
                "A claimed warm standby — a comparison point, never folded into a cold number."
            }
        }
    }

    /// The dispatch-window budgets this lane is published and gated against.
    ///
    /// [`validate_matrix_report`] and the published budget table both read
    /// this, so a budget cannot be changed in one and stale in the other.
    #[must_use]
    pub const fn budgets(self) -> LaneBudgets {
        match self {
            Self::PreparedCold | Self::PreparedColdMountHit => LaneBudgets {
                p50_ms: Some(PREPARED_COLD_P50_BUDGET_MS),
                p95_ms: Some(PREPARED_COLD_P95_BUDGET_MS),
                p99_ms: Some(PREPARED_COLD_P99_BUDGET_MS),
                hard_max_ms: Some(PREPARED_COLD_HARD_MAX_MS),
            },
            Self::WarmClaim => LaneBudgets {
                p50_ms: Some(WARM_CLAIM_P50_BUDGET_MS),
                p95_ms: None,
                p99_ms: Some(WARM_CLAIM_P99_BUDGET_MS),
                hard_max_ms: None,
            },
            Self::MountMiss | Self::ArtifactMiss => LaneBudgets {
                p50_ms: None,
                p95_ms: None,
                p99_ms: None,
                hard_max_ms: None,
            },
        }
    }
}

impl std::str::FromStr for LaunchLane {
    type Err = String;

    /// Parse a lane by its wire name. An unknown name errors and lists the
    /// real ones rather than falling back to `prepared_cold`: a mistyped lane
    /// that quietly measured something else is worse than no measurement.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        Self::ALL
            .into_iter()
            .find(|lane| lane.as_str() == trimmed)
            .ok_or_else(|| {
                let names: Vec<&str> = Self::ALL.iter().map(|lane| lane.as_str()).collect();
                format!("unknown launch lane {trimmed:?}; expected one of {names:?}")
            })
    }
}

/// Why a sample does not belong in the lane it was labeled with.
#[derive(Debug, Clone, PartialEq)]
pub enum LaneViolation {
    /// The sample came from an unoptimised binary.
    NotReleaseBuild { profile: BuildProfile },
    /// The sample's schema is not the one this consumer understands.
    SchemaMismatch { found: u32, expected: u32 },
    /// The report schema is not the current matrix schema.
    ReportSchemaMismatch { found: u32, expected: u32 },
    /// The current sample does not identify its selected root filesystem path.
    MissingRootStrategy,
    /// A warm sample omitted the required process-memory evidence.
    MissingWarmMemory,
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
    /// The launch came up without a capability it should have had.
    Degraded { missing: Vec<String> },
    /// The report does not contain enough repeated observations to publish a
    /// matrix result.
    InsufficientSamples { found: u32, required: u32 },
    /// The report was not produced with the required discarded warm-ups.
    WrongWarmup { found: u32, required: u32 },
    /// A percentile exceeded the lane's published budget.
    BudgetExceeded {
        lane: LaunchLane,
        percentile: &'static str,
        found_ms: f64,
        budget_ms: f64,
    },
    /// A prepared boot reached or crossed the strict per-sample ceiling.
    HardMaximumExceeded {
        lane: LaunchLane,
        found_ms: f64,
        limit_ms: f64,
    },
    /// The stored summary does not match the report's raw samples.
    NonCanonicalSummary,
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
            Self::ReportSchemaMismatch { found, expected } => write!(
                f,
                "cold-launch report schema {found} is not the expected {expected}"
            ),
            Self::MissingRootStrategy => write!(
                f,
                "launch sample does not identify its selected root filesystem strategy"
            ),
            Self::MissingWarmMemory => write!(
                f,
                "warm launch sample does not contain whole-VMM first-command memory evidence"
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
            Self::Degraded { missing } => write!(
                f,
                "launch came up without {}; a degraded launch is not a sample of a healthy one",
                missing.join(", ")
            ),
            Self::InsufficientSamples { found, required } => write!(
                f,
                "matrix lane has {found} measured samples; at least {required} are required"
            ),
            Self::WrongWarmup { found, required } => write!(
                f,
                "matrix lane discarded {found} warm-up samples; exactly {required} are required"
            ),
            Self::BudgetExceeded {
                lane,
                percentile,
                found_ms,
                budget_ms,
            } => write!(
                f,
                "lane {} {percentile} dispatch percentile {found_ms:.1}ms exceeds {budget_ms:.1}ms",
                lane.as_str()
            ),
            Self::HardMaximumExceeded {
                lane,
                found_ms,
                limit_ms,
            } => write!(
                f,
                "lane {} slowest boot dispatch was {found_ms:.1}ms; every boot must be under {limit_ms:.1}ms",
                lane.as_str()
            ),
            Self::NonCanonicalSummary => {
                f.write_str("cold-launch report summary does not match its raw samples")
            }
        }
    }
}

/// Validate a complete lane report for publication in the live backend matrix.
///
/// Per-sample lane validation happens while a benchmark runs. This second
/// gate is intentionally report-level: it prevents a one-off successful launch
/// from being presented as a repeated result and applies the same budget table
/// to every backend that produces the report.
pub fn validate_matrix_report(report: &ColdLaunchReport) -> Result<(), LaneViolation> {
    if report.schema_version != COLD_LAUNCH_SCHEMA_VERSION {
        return Err(LaneViolation::ReportSchemaMismatch {
            found: report.schema_version,
            expected: COLD_LAUNCH_SCHEMA_VERSION,
        });
    }
    if report.raw.len() < MIN_MATRIX_SAMPLES as usize {
        return Err(LaneViolation::InsufficientSamples {
            found: u32::try_from(report.raw.len()).unwrap_or(u32::MAX),
            required: MIN_MATRIX_SAMPLES,
        });
    }
    if report.warmup != MATRIX_WARMUP_SAMPLES {
        return Err(LaneViolation::WrongWarmup {
            found: report.warmup,
            required: MATRIX_WARMUP_SAMPLES,
        });
    }
    for sample in &report.raw {
        validate_lane(report.lane, &sample_to_launch_sample(sample))?;
    }
    let canonical = build_cold_launch_report(report.lane, report.warmup, report.raw.clone());
    if report.stats != canonical.stats || report.hard_requirement != canonical.hard_requirement {
        return Err(LaneViolation::NonCanonicalSummary);
    }
    validate_hard_boot_requirement(report)?;
    let measured = report.stats.dispatch_window_ms.by_percentile();
    for ((percentile, budget_ms), (_, found)) in report
        .lane
        .budgets()
        .by_percentile()
        .into_iter()
        .zip(measured)
    {
        if let Some(budget_ms) = budget_ms {
            require_budget(report.lane, percentile, found, budget_ms)?;
        }
    }
    Ok(())
}

/// Enforce the strict prepared-boot ceiling independently of publication-size
/// percentile validation.
///
/// This deliberately runs for indicative one-off reports too. "Always under"
/// cannot become conditional on collecting twenty observations first.
pub fn validate_hard_boot_requirement(report: &ColdLaunchReport) -> Result<(), LaneViolation> {
    let observed_max_ms = report
        .raw
        .iter()
        .map(|sample| sample.phases.dispatch_window_ms())
        .reduce(f64::max);
    if report.stats.dispatch_window_ms.max != observed_max_ms {
        return Err(LaneViolation::NonCanonicalSummary);
    }
    let expected = matches!(
        report.lane,
        LaunchLane::PreparedCold | LaunchLane::PreparedColdMountHit
    )
    .then(|| HardBootRequirement::prepared(observed_max_ms));
    if report.hard_requirement != expected {
        return Err(LaneViolation::NonCanonicalSummary);
    }
    let Some(requirement) = report.hard_requirement.as_ref() else {
        return Ok(());
    };
    if let Some(found_ms) = requirement.observed_max_ms {
        validate_hard_boot_timing(report.lane, found_ms)?;
    }
    Ok(())
}

/// Validate one observed dispatch duration against the lane's per-boot rule.
/// Acquisition and warm-claim lanes have different contracts and are left to
/// their own gates.
pub fn validate_hard_boot_timing(lane: LaunchLane, found_ms: f64) -> Result<(), LaneViolation> {
    if matches!(
        lane,
        LaunchLane::PreparedCold | LaunchLane::PreparedColdMountHit
    ) && found_ms >= PREPARED_COLD_HARD_MAX_MS
    {
        return Err(LaneViolation::HardMaximumExceeded {
            lane,
            found_ms,
            limit_ms: PREPARED_COLD_HARD_MAX_MS,
        });
    }
    Ok(())
}

fn require_budget(
    lane: LaunchLane,
    percentile: &'static str,
    found: Option<f64>,
    budget_ms: f64,
) -> Result<(), LaneViolation> {
    if let Some(found_ms) = found
        && found_ms > budget_ms
    {
        return Err(LaneViolation::BudgetExceeded {
            lane,
            percentile,
            found_ms,
            budget_ms,
        });
    }
    Ok(())
}

/// Reconstruct the producer shape needed by the per-sample gate from a report
/// sample. The report stores the resolved context and timing, not the original
/// path-bearing launch wire object, so only fields relevant to contamination
/// and lane identity are reconstructed here.
fn sample_to_launch_sample(sample: &ColdLaunchSample) -> LaunchSample {
    LaunchSample {
        schema_version: LAUNCH_SAMPLE_SCHEMA_VERSION,
        build_profile: BuildProfile::Release,
        mvm_version: sample.context.mvm_version.clone(),
        backend: sample.context.backend.clone(),
        os: sample.context.os.clone(),
        arch: sample.context.arch.clone(),
        launch_mode: sample.launch_mode,
        root_strategy: sample.context.root_strategy,
        sizing: sample.context.sizing,
        artifacts: sample.context.artifacts.clone(),
        work: sample.work,
        phases: sample.phases,
        sub_phases: sample.sub_phases,
        warm_first_command_memory: sample.warm_first_command_memory,
        backend_phases: sample.backend_phases.clone(),
        degraded: sample.degraded.clone(),
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
    if sample.root_strategy.is_none() {
        return Err(LaneViolation::MissingRootStrategy);
    }
    if sample.build_profile != BuildProfile::Release {
        return Err(LaneViolation::NotReleaseBuild {
            profile: sample.build_profile,
        });
    }
    // Refused for every lane, before the per-lane rules. The work flags catch a
    // launch that did more than its lane allows; this catches one that quietly
    // did less than a launch is supposed to. Both produce a plausible number
    // from a launch that was not the launch being measured.
    if !sample.degraded.is_empty() {
        return Err(LaneViolation::Degraded {
            missing: sample.degraded.clone(),
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
                "artifact_hash",
                "process_table_scan",
            ])?;
            require_cold(lane, sample)
        }
        LaunchLane::PreparedColdMountHit => {
            forbid(vec![
                "image_pull",
                "image_build",
                "mount_materialize",
                "warm_claim",
                "artifact_hash",
                "process_table_scan",
            ])?;
            require_cold(lane, sample)
        }
        LaunchLane::MountMiss => {
            forbid(vec![
                "image_pull",
                "image_build",
                "warm_claim",
                "artifact_hash",
                "process_table_scan",
            ])?;
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
            if sample.warm_first_command_memory.is_none() {
                return Err(LaneViolation::MissingWarmMemory);
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

/// Artifact measurements resolved outside the launch's timed window.
///
/// Missing artifact paths stay `None`: the launch sample is still useful for
/// timing, but the report makes the missing substrate evidence visible instead
/// of turning it into a fabricated zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactMeasurements {
    pub kernel_bytes: Option<u64>,
    pub initramfs_bytes: Option<u64>,
    pub runtime_overlay_bytes: Option<u64>,
    pub rootfs_bytes: Option<u64>,
    pub kernel_config: Option<KernelConfigMeasurement>,
}

/// Resolved kernel-config evidence attached to a launch report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelConfigMeasurement {
    pub path: String,
    pub builtin_symbols: u32,
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
    /// Root filesystem strategy selected by the capability/security tier gate.
    #[serde(default)]
    pub root_strategy: Option<crate::commands::vm::launch_sample::LaunchRootStrategy>,
    pub sizing: GuestSizing,
    pub filesystem: Option<String>,
    pub artifacts: ArtifactPaths,
    pub digests: ArtifactDigests,
    #[serde(default)]
    pub measurements: ArtifactMeasurements,
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
    /// Parent-observed process wall clock, from immediately before spawning
    /// `mvmctl` until it exits after command-level audit completion.
    #[serde(default)]
    pub command_lifecycle_ms: f64,
    pub phases: RunPhaseTimings,
    pub sub_phases: LaunchSubTimings,
    /// Whole-VMM warm-ready and first-command memory evidence.
    #[serde(default)]
    pub warm_first_command_memory: Option<WarmFirstCommandMemory>,
    /// Phases the backend recorded inside its own `start`.
    #[serde(default)]
    pub backend_phases: Vec<TracePhase>,
    /// Capabilities the launch came up without.
    #[serde(default)]
    pub degraded: Vec<String>,
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
    /// Slowest recorded sample. This is required to evaluate an "every boot"
    /// contract; no percentile, including p99, proves a hard maximum.
    #[serde(default)]
    pub max: Option<f64>,
}

impl SpanStats {
    /// The measured percentiles in the same order and with the same labels as
    /// [`LaneBudgets::by_percentile`], so a budget and its measurement can be
    /// zipped without either side naming a percentile as a string.
    #[must_use]
    pub const fn by_percentile(self) -> [(&'static str, Option<f64>); 3] {
        [("p50", self.p50), ("p95", self.p95), ("p99", self.p99)]
    }

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
            max: samples.iter().copied().reduce(f64::max),
        }
    }
}

/// Machine-readable statement and verdict for the prepared-boot invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimingMetric {
    DispatchWindowMs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementComparison {
    LessThan,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardBootRequirement {
    pub metric: TimingMetric,
    pub comparison: RequirementComparison,
    pub limit_ms: f64,
    pub observed_max_ms: Option<f64>,
    pub met: bool,
    pub remark: String,
}

impl HardBootRequirement {
    fn prepared(observed_max_ms: Option<f64>) -> Self {
        Self {
            metric: TimingMetric::DispatchWindowMs,
            comparison: RequirementComparison::LessThan,
            limit_ms: PREPARED_COLD_HARD_MAX_MS,
            observed_max_ms,
            met: observed_max_ms.is_some_and(|value| value < PREPARED_COLD_HARD_MAX_MS),
            remark: format!(
                "Every prepared boot must reach authenticated command dispatch in under {PREPARED_COLD_HARD_MAX_MS:.0} ms."
            ),
        }
    }
}

/// Percentiles for every span of one lane.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneStats {
    /// Admitted plan to command dispatch — the window the launch contract is
    /// set against.
    pub dispatch_window_ms: SpanStats,
    /// The shell-visible lifetime of the complete `mvmctl` child process.
    #[serde(default)]
    pub command_lifecycle_ms: SpanStats,
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
    /// One entry per backend-recorded phase, in the order the backend reported
    /// them. Names are backend-defined, so this is derived from the samples
    /// rather than from a fixed list.
    #[serde(default)]
    pub backend_phases: Vec<(String, SpanStats)>,
    /// Whole-VMM resident memory at warm readiness, in bytes.
    #[serde(default)]
    pub warm_ready_resident_bytes: SpanStats,
    /// Resident-memory growth during the first warm command, in bytes.
    #[serde(default)]
    pub warm_first_command_resident_growth_bytes: SpanStats,
    /// Resident-memory reclamation during the first warm command, in bytes.
    #[serde(default)]
    pub warm_first_command_resident_reclaimed_bytes: SpanStats,
    /// Minor faults during the first warm command, when the host exposes them.
    #[serde(default)]
    pub warm_first_command_minor_faults: SpanStats,
    /// Major faults during the first warm command, when the host exposes them.
    #[serde(default)]
    pub warm_first_command_major_faults: SpanStats,
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
    /// Present on lanes governed by the strict prepared-boot ceiling.
    #[serde(default)]
    pub hard_requirement: Option<HardBootRequirement>,
    pub raw: Vec<ColdLaunchSample>,
}

/// Every sub-phase name a report summarises, in the order they occur.
const SUB_PHASE_NAMES: [&str; 12] = [
    "mount_fingerprint",
    "mount_cache_lookup",
    "mount_materialize",
    "artifact_verify",
    "vmm_create",
    "guest_kernel_entry",
    "agent_auth",
    "first_dispatch",
    "cleanup_handoff",
    "stop_transient",
    "pool_replenish",
    "state_remove",
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
    let dispatch_window_ms = col(|s| s.phases.dispatch_window_ms());
    let hard_requirement = matches!(
        lane,
        LaunchLane::PreparedCold | LaunchLane::PreparedColdMountHit
    )
    .then(|| HardBootRequirement::prepared(dispatch_window_ms.max));
    ColdLaunchReport {
        schema_version: COLD_LAUNCH_SCHEMA_VERSION,
        lane,
        warmup,
        stats: LaneStats {
            dispatch_window_ms,
            command_lifecycle_ms: col(|s| s.command_lifecycle_ms),
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
            backend_phases: backend_phase_stats(&raw),
            warm_ready_resident_bytes: memory_stats(&raw, |memory| {
                memory.ready.resident_bytes as f64
            }),
            warm_first_command_resident_growth_bytes: memory_stats(&raw, |memory| {
                memory.delta.resident_growth_bytes as f64
            }),
            warm_first_command_resident_reclaimed_bytes: memory_stats(&raw, |memory| {
                memory.delta.resident_reclaimed_bytes as f64
            }),
            warm_first_command_minor_faults: memory_counter_stats(&raw, |memory| {
                memory.delta.minor_faults
            }),
            warm_first_command_major_faults: memory_counter_stats(&raw, |memory| {
                memory.delta.major_faults
            }),
        },
        hard_requirement,
        raw,
    }
}

fn memory_stats(
    raw: &[ColdLaunchSample],
    value: impl Fn(&WarmFirstCommandMemory) -> f64,
) -> SpanStats {
    SpanStats::from_samples(
        &raw.iter()
            .filter_map(|sample| sample.warm_first_command_memory.as_ref().map(&value))
            .collect::<Vec<_>>(),
    )
}

fn memory_counter_stats(
    raw: &[ColdLaunchSample],
    value: impl Fn(&WarmFirstCommandMemory) -> Option<u64>,
) -> SpanStats {
    SpanStats::from_samples(
        &raw.iter()
            .filter_map(|sample| {
                sample
                    .warm_first_command_memory
                    .as_ref()
                    .and_then(&value)
                    .map(|value| value as f64)
            })
            .collect::<Vec<_>>(),
    )
}

/// Summarise the backend-recorded phases across a lane's samples.
///
/// The name set is discovered from the samples, in first-seen order, because
/// each backend names its own phases; a fixed list here would silently drop a
/// phase the moment a second backend is traced.
fn backend_phase_stats(raw: &[ColdLaunchSample]) -> Vec<(String, SpanStats)> {
    let mut order: Vec<String> = Vec::new();
    for sample in raw {
        for phase in &sample.backend_phases {
            if !order.contains(&phase.name) {
                order.push(phase.name.clone());
            }
        }
    }
    order
        .into_iter()
        .map(|name| {
            let values: Vec<f64> = raw
                .iter()
                .filter_map(|sample| {
                    sample
                        .backend_phases
                        .iter()
                        .find(|phase| phase.name == name)
                        .map(|phase| phase.ms)
                })
                .collect();
            let stats = SpanStats::from_samples(&values);
            (name, stats)
        })
        .collect()
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
            root_strategy: Some(LaunchRootStrategy::BlockExt4),
            sizing: GuestSizing {
                cpus: 2,
                memory_mib: 512,
                mem_initial_mib: None,
            },
            artifacts: ArtifactPaths::default(),
            work: LaunchWork::default(),
            phases: phases(148.0),
            sub_phases: LaunchSubTimings::default(),
            warm_first_command_memory: None,
            backend_phases: Vec::new(),
            degraded: Vec::new(),
        }
    }

    fn warm_memory() -> WarmFirstCommandMemory {
        let ready = ProcessMemorySnapshot {
            resident_bytes: 10,
            minor_faults: Some(2),
            major_faults: Some(0),
        };
        let after_first_command = ProcessMemorySnapshot {
            resident_bytes: 14,
            minor_faults: Some(5),
            major_faults: Some(1),
        };
        WarmFirstCommandMemory {
            pid: 42,
            ready,
            after_first_command,
            delta: ProcessMemoryDelta::between(ready, after_first_command),
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
                root_strategy: Some(LaunchRootStrategy::BlockExt4),
                sizing: GuestSizing {
                    cpus: 2,
                    memory_mib: 512,
                    mem_initial_mib: None,
                },
                filesystem: Some("apfs".to_string()),
                artifacts: ArtifactPaths::default(),
                digests: ArtifactDigests::default(),
                measurements: ArtifactMeasurements::default(),
            },
            cache: CacheState {
                artifacts_cached: true,
                mount: MountCacheState::NotUsed,
            },
            work: LaunchWork::default(),
            launch_mode: LaunchMode::Cold,
            command_lifecycle_ms: total_ms + 25.0,
            phases: phases(total_ms),
            sub_phases: LaunchSubTimings {
                vmm_create_ms: Some(total_ms / 2.0),
                ..LaunchSubTimings::default()
            },
            warm_first_command_memory: None,
            backend_phases: vec![TracePhase {
                name: "boot_confirm".to_string(),
                ms: total_ms / 4.0,
            }],
            degraded: Vec::new(),
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
            artifact_bytes_hashed: 1_205_739_520,
            process_table_scans: 1,
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
                    "warm_claim",
                    "artifact_hash",
                    "process_table_scan"
                ],
            }
        );
    }

    /// The regression this gate exists for: re-reading an already-cached
    /// artifact to recompute a digest is not a pull, a build, a mount
    /// materialization, or a warm claim, so before this flag existed such a
    /// launch reported itself as a clean prepared-cold sample. Its cost is
    /// linear in artifact size, which is why it stayed invisible on a small
    /// image and dominated a large one.
    #[test]
    fn prepared_cold_rejects_a_launch_that_re_hashed_a_cached_artifact() {
        let mut sample = launch_sample();
        sample.work.artifact_bytes_hashed = 1_205_739_520;
        let err = validate_lane(LaunchLane::PreparedCold, &sample).unwrap_err();
        assert_eq!(
            err,
            LaneViolation::ForbiddenWork {
                lane: LaunchLane::PreparedCold,
                performed: vec!["artifact_hash"],
            }
        );
        assert!(err.to_string().contains("artifact_hash"));
    }

    /// Zero is the prepared state, and it must not be confused with "the
    /// counter was never populated": both read as no work, and only the first
    /// is a claim. A sample that hashed nothing passes, which is what makes
    /// the fixed launch path provable rather than merely faster.
    #[test]
    fn prepared_cold_accepts_a_launch_that_hashed_nothing() {
        let mut sample = launch_sample();
        sample.work.artifact_bytes_hashed = 0;
        assert_eq!(validate_lane(LaunchLane::PreparedCold, &sample), Ok(()));
    }

    /// The mount-miss lane materializes a mount image and is expected to; it
    /// still boots prepared artifacts, so a rootfs re-hash contaminates it the
    /// same way.
    #[test]
    fn mount_miss_still_rejects_a_re_hashed_artifact() {
        let mut sample = launch_sample();
        sample.work.mount_materialize = true;
        sample.work.artifact_bytes_hashed = 1_205_739_520;
        let err = validate_lane(LaunchLane::MountMiss, &sample).unwrap_err();
        assert_eq!(
            err,
            LaneViolation::ForbiddenWork {
                lane: LaunchLane::MountMiss,
                performed: vec!["artifact_hash"],
            }
        );
    }

    /// The other half of the same finding: a process-table snapshot is
    /// maintenance whose cost belongs to a run that spawns a helper, not to one
    /// that resolved everything from cache. Like the re-hash, it is not a pull,
    /// a build, a materialization, or a claim.
    #[test]
    fn prepared_cold_rejects_a_launch_that_walked_the_process_table() {
        let mut sample = launch_sample();
        sample.work.process_table_scans = 1;
        let err = validate_lane(LaunchLane::PreparedCold, &sample).unwrap_err();
        assert_eq!(
            err,
            LaneViolation::ForbiddenWork {
                lane: LaunchLane::PreparedCold,
                performed: vec!["process_table_scan"],
            }
        );
        assert!(err.to_string().contains("process_table_scan"));
    }

    /// The artifact-miss lane is the one that legitimately hashes: it acquires
    /// and prepares the image, so reading it end-to-end is the work being
    /// measured rather than work being repeated.
    #[test]
    fn artifact_miss_permits_hashing_because_that_lane_is_the_acquisition() {
        let mut sample = launch_sample();
        sample.work.image_pull = true;
        sample.work.artifact_bytes_hashed = 1_205_739_520;
        // The same lane spawns a builder VM when the ext4 writer cannot emit a
        // tree, so it reaps before doing so; that sweep belongs to this lane.
        sample.work.process_table_scans = 1;
        assert_eq!(validate_lane(LaunchLane::ArtifactMiss, &sample), Ok(()));
    }

    #[test]
    fn a_degraded_launch_is_refused_by_every_lane() {
        // The failure this exists for: a launch whose host-services
        // registration silently failed still runs and still produces a
        // perfectly plausible timing, so nothing about the number reveals that
        // it measured a launch missing a security-relevant capability.
        for lane in LaunchLane::ALL {
            let mut sample = launch_sample();
            sample.work.warm_claim = true;
            sample.launch_mode = LaunchMode::Warm;
            sample.work.mount_materialize = true;
            sample.work.image_pull = true;
            sample.degraded = vec!["host_services".to_string()];
            assert_eq!(
                validate_lane(lane, &sample),
                Err(LaneViolation::Degraded {
                    missing: vec!["host_services".to_string()]
                }),
                "lane {} must refuse a degraded launch",
                lane.as_str()
            );
        }
    }

    #[test]
    fn degradation_is_refused_before_the_per_lane_rules() {
        // Otherwise a degraded launch that also belongs in its lane would pass.
        let mut sample = launch_sample();
        sample.degraded = vec!["host_services".to_string()];
        let err = validate_lane(LaunchLane::PreparedCold, &sample).unwrap_err();
        assert!(err.to_string().contains("host_services"), "{err}");
        assert!(err.to_string().contains("degraded launch"), "{err}");
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
        assert_eq!(
            validate_lane(LaunchLane::WarmClaim, &sample),
            Err(LaneViolation::MissingWarmMemory)
        );
        sample.warm_first_command_memory = Some(warm_memory());
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
    fn a_missing_root_strategy_is_rejected() {
        let mut sample = launch_sample();
        sample.root_strategy = None;
        assert_eq!(
            validate_lane(LaunchLane::PreparedCold, &sample),
            Err(LaneViolation::MissingRootStrategy)
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
        assert_eq!(report.stats.command_lifecycle_ms.p50, Some(275.0));
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
    fn report_aggregates_whole_vmm_warm_memory_evidence() {
        let mut sample = cold_sample(1, 90.0);
        sample.launch_mode = LaunchMode::Warm;
        sample.work.warm_claim = true;
        sample.warm_first_command_memory = Some(warm_memory());
        let report = build_cold_launch_report(LaunchLane::WarmClaim, 2, vec![sample]);

        assert_eq!(report.stats.warm_ready_resident_bytes.p50, Some(10.0));
        assert_eq!(
            report.stats.warm_first_command_resident_growth_bytes.p50,
            Some(4.0)
        );
        assert_eq!(
            report.stats.warm_first_command_resident_reclaimed_bytes.p50,
            Some(0.0)
        );
        assert_eq!(report.stats.warm_first_command_minor_faults.p50, Some(3.0));
        assert_eq!(report.stats.warm_first_command_major_faults.p50, Some(1.0));
    }

    #[test]
    fn matrix_gate_requires_twenty_samples_and_two_warmups() {
        let report = build_cold_launch_report(
            LaunchLane::PreparedCold,
            MATRIX_WARMUP_SAMPLES,
            (1..MIN_MATRIX_SAMPLES)
                .map(|number| cold_sample(number, 100.0))
                .collect(),
        );
        assert_eq!(
            validate_matrix_report(&report),
            Err(LaneViolation::InsufficientSamples {
                found: MIN_MATRIX_SAMPLES - 1,
                required: MIN_MATRIX_SAMPLES,
            })
        );

        let report = build_cold_launch_report(
            LaunchLane::PreparedCold,
            1,
            (1..=MIN_MATRIX_SAMPLES)
                .map(|number| cold_sample(number, 100.0))
                .collect(),
        );
        assert_eq!(
            validate_matrix_report(&report),
            Err(LaneViolation::WrongWarmup {
                found: 1,
                required: MATRIX_WARMUP_SAMPLES,
            })
        );
    }

    #[test]
    fn matrix_gate_applies_the_hard_maximum_before_percentile_diagnostics() {
        let report = build_cold_launch_report(
            LaunchLane::PreparedCold,
            MATRIX_WARMUP_SAMPLES,
            (1..=MIN_MATRIX_SAMPLES)
                .map(|number| {
                    let mut sample = cold_sample(number, 301.0);
                    sample.phases.backend_start_ms = 271.0;
                    sample
                })
                .collect(),
        );
        assert_eq!(
            validate_matrix_report(&report),
            Err(LaneViolation::HardMaximumExceeded {
                lane: LaunchLane::PreparedCold,
                found_ms: 301.0,
                limit_ms: PREPARED_COLD_HARD_MAX_MS,
            })
        );
    }

    #[test]
    fn percentile_budget_check_is_inclusive_at_its_boundary() {
        assert_eq!(
            require_budget(
                LaunchLane::PreparedCold,
                "p50",
                Some(PREPARED_COLD_P50_BUDGET_MS),
                PREPARED_COLD_P50_BUDGET_MS,
            ),
            Ok(())
        );
        assert_eq!(
            require_budget(
                LaunchLane::PreparedCold,
                "p50",
                Some(PREPARED_COLD_P50_BUDGET_MS + 0.1),
                PREPARED_COLD_P50_BUDGET_MS,
            ),
            Err(LaneViolation::BudgetExceeded {
                lane: LaunchLane::PreparedCold,
                percentile: "p50",
                found_ms: PREPARED_COLD_P50_BUDGET_MS + 0.1,
                budget_ms: PREPARED_COLD_P50_BUDGET_MS,
            })
        );
    }

    #[test]
    fn hard_boot_requirement_rejects_one_slow_sample_below_publication_floor() {
        let mut fast = cold_sample(1, 150.0);
        fast.phases.backend_start_ms = 169.9;
        fast.phases.vsock_wait_ms = 30.0;
        let fast_report = build_cold_launch_report(LaunchLane::PreparedCold, 0, vec![fast]);
        assert_eq!(validate_hard_boot_requirement(&fast_report), Ok(()));
        assert_eq!(fast_report.stats.dispatch_window_ms.max, Some(199.9));
        assert!(
            fast_report
                .hard_requirement
                .as_ref()
                .is_some_and(|requirement| requirement.met)
        );

        let mut boundary = cold_sample(1, 150.0);
        boundary.phases.backend_start_ms = 170.0;
        boundary.phases.vsock_wait_ms = 30.0;
        let boundary_report = build_cold_launch_report(LaunchLane::PreparedCold, 0, vec![boundary]);
        assert_eq!(
            validate_hard_boot_requirement(&boundary_report),
            Err(LaneViolation::HardMaximumExceeded {
                lane: LaunchLane::PreparedCold,
                found_ms: 200.0,
                limit_ms: PREPARED_COLD_HARD_MAX_MS,
            })
        );
        assert!(
            !boundary_report
                .hard_requirement
                .as_ref()
                .is_some_and(|requirement| requirement.met)
        );
    }

    #[test]
    fn acquisition_lanes_do_not_claim_the_prepared_boot_requirement() {
        let report =
            build_cold_launch_report(LaunchLane::ArtifactMiss, 0, vec![cold_sample(1, 500.0)]);
        assert_eq!(report.hard_requirement, None);
        assert_eq!(validate_hard_boot_requirement(&report), Ok(()));
    }

    #[test]
    fn report_roundtrips_through_json() {
        let report =
            build_cold_launch_report(LaunchLane::PreparedCold, 2, vec![cold_sample(1, 90.0)]);
        let json = serde_json::to_string(&report).unwrap();
        let back: ColdLaunchReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["hard_requirement"]["comparison"], "less_than");
        assert_eq!(value["stats"]["dispatch_window_ms"]["max"], 130.0);
    }

    #[test]
    fn lane_names_round_trip_and_reject_a_typo() {
        for lane in LaunchLane::ALL {
            assert_eq!(lane.as_str().parse::<LaunchLane>(), Ok(lane));
        }
        assert_eq!(
            "  prepared_cold  ".parse::<LaunchLane>(),
            Ok(LaunchLane::PreparedCold)
        );
        let err = "prepared-cold".parse::<LaunchLane>().unwrap_err();
        assert!(err.contains("unknown launch lane"), "{err}");
        assert!(err.contains("prepared_cold"), "{err}");
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
