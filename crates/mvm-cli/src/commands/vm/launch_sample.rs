//! The machine-readable sample one transient launch emits about itself: the
//! build profile that produced it, the backend and artifacts it booted, the
//! expensive work it performed, and the per-phase spans.
//!
//! The `MVM_PHASE_TIMING` stderr line stays a human diagnostic. This is the
//! wire form a benchmark consumes, so it is a serde schema with its own
//! rejection rules rather than a string another process greps: a launch
//! measurement that depends on parsing prose breaks silently the first time
//! the prose changes.
//!
//! Written only when `MVM_LAUNCH_SAMPLE_JSON` names a path, so a normal run
//! pays nothing.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::phase_timing::{LaunchMode, RunPhaseTimings};

/// Env var naming the file this process writes its launch sample to.
pub const LAUNCH_SAMPLE_ENV: &str = "MVM_LAUNCH_SAMPLE_JSON";

/// Sample schema version. A consumer that reads a different version refuses
/// the sample as incomparable rather than mis-reading it.
pub const LAUNCH_SAMPLE_SCHEMA_VERSION: u32 = 1;

/// Cargo profile the `mvmctl` binary that produced a sample was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildProfile {
    /// Unoptimised. A launch measured here reports the compiler, not the
    /// launch path, so a benchmark refuses it.
    Debug,
    /// Optimised — the only profile a launch measurement may come from.
    Release,
}

impl BuildProfile {
    /// The profile of the binary evaluating this call.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(debug_assertions) {
            Self::Debug
        } else {
            Self::Release
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }
}

/// Expensive work a launch actually performed.
///
/// A lane gate reads these flags, never a span: an absent span means "not
/// instrumented on this path", while a flag is a positive statement that the
/// work ran. Conflating the two would let an uninstrumented image pull pass
/// as a prepared-cold launch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LaunchWork {
    /// A registry fetch ran during this process.
    pub image_pull: bool,
    /// A flake/image build ran during this process.
    pub image_build: bool,
    /// A mount image was materialized rather than attached from cache.
    pub mount_materialize: bool,
    /// The launch was satisfied by claiming a warm standby.
    pub warm_claim: bool,
}

impl LaunchWork {
    /// Names of every kind of work performed, in declaration order. Empty for
    /// a launch that did none.
    #[must_use]
    pub fn performed(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.image_pull {
            names.push("image_pull");
        }
        if self.image_build {
            names.push("image_build");
        }
        if self.mount_materialize {
            names.push("mount_materialize");
        }
        if self.warm_claim {
            names.push("warm_claim");
        }
        names
    }

    /// Whether the launch performed none of the work a prepared-cold sample
    /// must exclude.
    #[must_use]
    pub fn is_prepared(&self) -> bool {
        self.performed().is_empty()
    }
}

/// Process-wide record of expensive acquisition work.
///
/// The registry fetch and the flake build sit many layers away from the
/// runner that reports the sample, and threading a flag back through every
/// one of them would be a wide refactor in service of a diagnostic. Two
/// atomics, set once and never cleared, keep the report honest instead. Set
/// once means a sample can only ever over-report work, never under-report it,
/// which is the safe direction for a gate that refuses contaminated samples.
struct WorkRecorder {
    image_pull: AtomicBool,
    image_build: AtomicBool,
}

static WORK: WorkRecorder = WorkRecorder {
    image_pull: AtomicBool::new(false),
    image_build: AtomicBool::new(false),
};

/// Record that this process fetched image bytes from a registry.
pub fn record_image_pull() {
    WORK.image_pull.store(true, Ordering::Relaxed);
}

/// Record that this process ran an image/flake build.
pub fn record_image_build() {
    WORK.image_build.store(true, Ordering::Relaxed);
}

/// Collapse the recorded acquisition work with the two flags the launch
/// itself observes.
#[must_use]
pub fn recorded_work(mount_materialize: bool, warm_claim: bool) -> LaunchWork {
    LaunchWork {
        image_pull: WORK.image_pull.load(Ordering::Relaxed),
        image_build: WORK.image_build.load(Ordering::Relaxed),
        mount_materialize,
        warm_claim,
    }
}

/// Host paths of the immutable artifacts a launch booted.
///
/// Paths, not digests: hashing them is I/O the measured launch must not pay.
/// A consumer resolves digests from these once, outside the timed window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactPaths {
    pub kernel: Option<String>,
    pub initramfs: Option<String>,
    pub runtime_overlay: Option<String>,
    pub rootfs: Option<String>,
}

/// Guest sizing the launch was configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestSizing {
    pub cpus: u32,
    pub memory_mib: u32,
    #[serde(default)]
    pub mem_initial_mib: Option<u32>,
}

/// Per-phase spans below the coarse run buckets, milliseconds.
///
/// Every field is optional and `None` means "no span was recorded" — either
/// the work did not run or this path does not instrument it. It is never
/// reported as `0.0`, because a zero span and an absent one are different
/// facts and a report that conflates them lies about where the time went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LaunchSubTimings {
    /// Hashing a `--mount` source directory into a cache key.
    pub mount_fingerprint_ms: Option<f64>,
    /// Looking a mount fingerprint up in the mount-image cache.
    pub mount_cache_lookup_ms: Option<f64>,
    /// Writing a mount ext4 image because the cache missed.
    pub mount_materialize_ms: Option<f64>,
    /// Verity sidecar probe and roothash read for the resolved rootfs.
    pub artifact_verify_ms: Option<f64>,
    /// The backend's own VM creation call, start to return.
    ///
    /// How much of guest boot this contains is backend-defined, and on the
    /// measured backends it contains most of it: HVF's `start` polls for the
    /// supervisor's PID file, so it returns at *boot confirmed*, not at
    /// vCPU-start. Separating VMM setup from guest boot is therefore not
    /// possible at this seam — it needs marks inside the driver.
    pub vmm_create_ms: Option<f64>,
    /// The backend's `start` returning to the start of the readiness attempt
    /// that succeeded.
    ///
    /// This is the residual wait after `start` returns, so on a backend whose
    /// `start` already confirms boot it collapses toward zero and a
    /// near-zero value here means "the guest was already up", not "the kernel
    /// booted instantly". Bounded below by the readiness poll interval.
    pub guest_kernel_entry_ms: Option<f64>,
    /// The successful agent handshake: connect plus authenticated ping.
    pub agent_auth_ms: Option<f64>,
    /// Establishing the channel the first guest command is dispatched over,
    /// excluding the command's own runtime.
    pub first_dispatch_ms: Option<f64>,
    /// Foreground teardown of the backend VM.
    pub cleanup_handoff_ms: Option<f64>,
}

impl LaunchSubTimings {
    /// A stable, greppable line carrying only the spans that were recorded.
    /// A run that recorded none renders as the bare prefix, which reads as
    /// "nothing below the coarse buckets was measured".
    #[must_use]
    pub fn render(&self) -> String {
        let mut line = String::from("[mvm] phase-timing-detail:");
        for (name, value) in self.recorded() {
            line.push_str(&format!(" {name}={value:.1}ms"));
        }
        line
    }

    /// Recorded spans in declaration order, as `(name, milliseconds)`.
    #[must_use]
    pub fn recorded(&self) -> Vec<(&'static str, f64)> {
        [
            ("mount_fingerprint", self.mount_fingerprint_ms),
            ("mount_cache_lookup", self.mount_cache_lookup_ms),
            ("mount_materialize", self.mount_materialize_ms),
            ("artifact_verify", self.artifact_verify_ms),
            ("vmm_create", self.vmm_create_ms),
            ("guest_kernel_entry", self.guest_kernel_entry_ms),
            ("agent_auth", self.agent_auth_ms),
            ("first_dispatch", self.first_dispatch_ms),
            ("cleanup_handoff", self.cleanup_handoff_ms),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.map(|ms| (name, ms)))
        .collect()
    }
}

/// One launch, as the launching process saw it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSample {
    pub schema_version: u32,
    pub build_profile: BuildProfile,
    /// `mvmctl`'s own version. For the in-house VMM this is also the VMM
    /// version, since that VMM ships inside this binary.
    pub mvm_version: String,
    pub backend: String,
    pub os: String,
    pub arch: String,
    pub launch_mode: LaunchMode,
    pub sizing: GuestSizing,
    pub artifacts: ArtifactPaths,
    pub work: LaunchWork,
    pub phases: RunPhaseTimings,
    pub sub_phases: LaunchSubTimings,
}

/// The path this process should write its launch sample to, if the operator
/// asked for one. An empty or whitespace-only value is treated as unset so a
/// blank export does not create a file named after nothing.
#[must_use]
pub fn sample_path_from_env() -> Option<PathBuf> {
    sample_path_from(std::env::var(LAUNCH_SAMPLE_ENV).ok().as_deref())
}

/// Pure over the raw env value so the gate is testable without mutating
/// process env.
fn sample_path_from(value: Option<&str>) -> Option<PathBuf> {
    let trimmed = value?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// Serialize `sample` to `path`, creating parent directories.
pub fn write_sample(path: &Path, sample: &LaunchSample) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating launch sample dir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(sample).context("serializing launch sample")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))
}

/// Read a launch sample a `mvmctl` process wrote.
pub fn read_sample(path: &Path) -> Result<LaunchSample> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading launch sample {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing launch sample {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> LaunchSample {
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
            artifacts: ArtifactPaths {
                kernel: Some("/k".to_string()),
                initramfs: None,
                runtime_overlay: None,
                rootfs: Some("/r".to_string()),
            },
            work: LaunchWork::default(),
            phases: RunPhaseTimings {
                launch_mode: LaunchMode::Cold,
                resolve_ms: 1.0,
                drives_ms: 2.0,
                admit_ms: 3.0,
                pool_wait_ms: 0.0,
                claim_ms: 0.0,
                backend_start_ms: 4.0,
                vsock_wait_ms: 5.0,
                warm_window_ms: 9.0,
                command_ms: 6.0,
                teardown_ms: 7.0,
                total_ms: 28.0,
            },
            sub_phases: LaunchSubTimings {
                vmm_create_ms: Some(3.5),
                agent_auth_ms: Some(1.25),
                ..LaunchSubTimings::default()
            },
        }
    }

    #[test]
    fn sample_roundtrips_through_json() {
        let original = sample();
        let json = serde_json::to_string(&original).unwrap();
        let back: LaunchSample = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn sample_rejects_an_unknown_field() {
        let mut value: serde_json::Value = serde_json::to_value(sample()).unwrap();
        value["surprise"] = serde_json::Value::Bool(true);
        let err = serde_json::from_value::<LaunchSample>(value).unwrap_err();
        assert!(
            err.to_string().contains("surprise"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn write_then_read_sample_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("sample.json");
        write_sample(&path, &sample()).unwrap();
        assert_eq!(read_sample(&path).unwrap(), sample());
    }

    #[test]
    fn read_sample_reports_a_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_sample(&tmp.path().join("absent.json")).unwrap_err();
        assert!(
            err.to_string().contains("absent.json"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn sample_path_ignores_a_blank_value() {
        assert_eq!(sample_path_from(None), None);
        assert_eq!(sample_path_from(Some("")), None);
        assert_eq!(sample_path_from(Some("   ")), None);
        assert_eq!(
            sample_path_from(Some(" /tmp/s.json ")),
            Some(PathBuf::from("/tmp/s.json"))
        );
    }

    #[test]
    fn work_lists_what_it_performed() {
        assert!(LaunchWork::default().is_prepared());
        assert!(LaunchWork::default().performed().is_empty());

        let contaminated = LaunchWork {
            image_pull: true,
            image_build: false,
            mount_materialize: true,
            warm_claim: false,
        };
        assert!(!contaminated.is_prepared());
        assert_eq!(
            contaminated.performed(),
            vec!["image_pull", "mount_materialize"]
        );
    }

    #[test]
    fn recorded_work_reflects_the_process_recorder() {
        // One test owns the process-wide recorder: the flags are set-once by
        // design, so a second test asserting "unset" would race this one.
        assert!(!recorded_work(false, false).image_build);
        record_image_pull();
        record_image_build();
        let work = recorded_work(true, true);
        assert_eq!(
            work,
            LaunchWork {
                image_pull: true,
                image_build: true,
                mount_materialize: true,
                warm_claim: true,
            }
        );
    }

    #[test]
    fn sub_timings_render_only_recorded_spans() {
        let empty = LaunchSubTimings::default();
        assert_eq!(empty.render(), "[mvm] phase-timing-detail:");
        assert!(empty.recorded().is_empty());

        let some = LaunchSubTimings {
            artifact_verify_ms: Some(0.4),
            vmm_create_ms: Some(120.0),
            cleanup_handoff_ms: Some(12.75),
            ..LaunchSubTimings::default()
        };
        assert_eq!(
            some.render(),
            "[mvm] phase-timing-detail: artifact_verify=0.4ms vmm_create=120.0ms cleanup_handoff=12.8ms"
        );
        assert_eq!(
            some.recorded(),
            vec![
                ("artifact_verify", 0.4),
                ("vmm_create", 120.0),
                ("cleanup_handoff", 12.75),
            ]
        );
    }

    #[test]
    fn build_profile_names_are_stable() {
        assert_eq!(BuildProfile::Debug.as_str(), "debug");
        assert_eq!(BuildProfile::Release.as_str(), "release");
        // The running test binary is unoptimised unless the suite is built
        // with `--release`; either way `current()` must agree with the cfg.
        let expected = if cfg!(debug_assertions) {
            BuildProfile::Debug
        } else {
            BuildProfile::Release
        };
        assert_eq!(BuildProfile::current(), expected);
    }
}
