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

use anyhow::{Context, Result};
use mvm_core::launch_trace::TracePhase;
use serde::{Deserialize, Serialize};

use super::phase_timing::{LaunchMode, RunPhaseTimings};

/// Env var naming the file this process writes its launch sample to. Shared
/// with the backend-side trace gate so the two can never disagree about
/// whether a launch is being measured.
pub use mvm_core::launch_trace::LAUNCH_SAMPLE_ENV;

/// Sample schema version. A consumer that reads a different version refuses
/// the sample as incomparable rather than mis-reading it.
pub const LAUNCH_SAMPLE_SCHEMA_VERSION: u32 = 4;

/// Point-in-time memory counters for the host process that owns a VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMemorySnapshot {
    /// Host resident bytes. Linux records RSS; macOS records physical
    /// footprint.
    pub resident_bytes: u64,
    /// Process-wide minor page faults on platforms that expose the counter.
    pub minor_faults: Option<u64>,
    /// Process-wide major page faults on platforms that expose the counter.
    pub major_faults: Option<u64>,
}

/// Change in process memory counters across the first guest command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMemoryDelta {
    /// Resident bytes added between the two samples.
    pub resident_growth_bytes: u64,
    /// Resident bytes released between the two samples.
    pub resident_reclaimed_bytes: u64,
    /// Minor page faults incurred between samples, when available.
    pub minor_faults: Option<u64>,
    /// Major page faults incurred between samples, when available.
    pub major_faults: Option<u64>,
}

impl ProcessMemoryDelta {
    /// Compute a non-negative delta while preserving counter unavailability.
    #[must_use]
    pub fn between(before: ProcessMemorySnapshot, after: ProcessMemorySnapshot) -> Self {
        Self {
            resident_growth_bytes: after.resident_bytes.saturating_sub(before.resident_bytes),
            resident_reclaimed_bytes: before.resident_bytes.saturating_sub(after.resident_bytes),
            minor_faults: counter_delta(before.minor_faults, after.minor_faults),
            major_faults: counter_delta(before.major_faults, after.major_faults),
        }
    }
}

fn counter_delta(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    before
        .zip(after)
        .map(|(before, after)| after.saturating_sub(before))
}

/// Whole-VMM resident memory observed after warm readiness and after its first command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WarmFirstCommandMemory {
    /// Host process sampled for both observations.
    pub pid: u32,
    /// Snapshot after the warm readiness barrier and before command dispatch.
    pub ready: ProcessMemorySnapshot,
    /// Snapshot immediately after the first guest command returns.
    pub after_first_command: ProcessMemorySnapshot,
    /// Derived change from `ready` to `after_first_command`.
    pub delta: ProcessMemoryDelta,
}

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
    /// Bytes read end-to-end to digest an artifact during this launch.
    ///
    /// A prepared launch boots artifacts whose digests are already cached, so
    /// this is zero on that lane. It is a count and not a flag because the
    /// number identifies the artifact: a re-read of a 1.1 GB rootfs and a
    /// re-read of an 8 MB kernel are the same boolean and very different
    /// launches.
    pub artifact_bytes_hashed: u64,
    /// Host process-table snapshots taken during this launch.
    ///
    /// Zero on a prepared launch: nothing it does spawns a helper, so nothing
    /// it does needs to reap one. Counted for the same reason as the bytes
    /// above — the cost is real, invisible in a digest or a boot, and belongs
    /// to maintenance rather than to the launch.
    pub process_table_scans: u64,
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
        if self.artifact_bytes_hashed > 0 {
            names.push("artifact_hash");
        }
        if self.process_table_scans > 0 {
            names.push("process_table_scan");
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

/// Collapse the process-wide acquisition record with the two flags the launch
/// itself observes. The acquisition half lives in `mvm-core` so the crates that
/// actually pull and build can report it.
#[must_use]
pub fn recorded_work(mount_materialize: bool, warm_claim: bool) -> LaunchWork {
    let acquired = mvm_core::launch_trace::recorded_acquisition();
    LaunchWork {
        image_pull: acquired.image_pull,
        image_build: acquired.image_build,
        mount_materialize,
        warm_claim,
        artifact_bytes_hashed: acquired.artifact_bytes_hashed,
        process_table_scans: acquired.process_table_scans,
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

/// Root filesystem strategy selected for this launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchRootStrategy {
    /// Boot the unpacked OCI tree through a read-only virtio-fs root.
    VirtiofsRoot,
    /// Boot a materialized ext4 block image, optionally protected by dm-verity.
    BlockExt4,
}

impl From<mvm_build::run_image::RootStrategy> for LaunchRootStrategy {
    fn from(strategy: mvm_build::run_image::RootStrategy) -> Self {
        match strategy {
            mvm_build::run_image::RootStrategy::VirtiofsRoot => Self::VirtiofsRoot,
            mvm_build::run_image::RootStrategy::BlockExt4 => Self::BlockExt4,
        }
    }
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
    /// Synthesizing, signing and recording the admitted plan.
    ///
    /// The `admit` bucket was a window with no named parts, so a launch that
    /// spent it somewhere unexpected could only say how long, never where.
    pub admit_plan_ms: Option<f64>,
    /// Attaching the cached runtime overlay.
    pub attach_overlay_ms: Option<f64>,
    /// Attaching the cached universal initramfs.
    pub attach_initramfs_ms: Option<f64>,
    /// The backend's own VM creation call, start to return.
    ///
    /// How much of guest boot this contains is backend-defined: HVF's `start`
    /// returns once the supervisor confirms boot by writing its PID file, so
    /// this covers VMM creation and the earliest part of guest boot but not
    /// the wait for a serving agent. `backend_phases` breaks it down further.
    pub vmm_create_ms: Option<f64>,
    /// The backend's `start` returning to the start of the readiness attempt
    /// that succeeded — the remaining guest boot, bounded below by the
    /// readiness poll interval.
    ///
    /// A near-zero value means the guest was already serving by the time the
    /// first poll ran, not that the kernel booted instantly. Slow post-boot
    /// work between `start` and the first poll masks this span entirely, so
    /// read it together with whatever ran in between.
    pub guest_kernel_entry_ms: Option<f64>,
    /// The successful agent handshake: connect plus authenticated ping.
    pub agent_auth_ms: Option<f64>,
    /// Establishing the channel the first guest command is dispatched over,
    /// excluding the command's own runtime.
    pub first_dispatch_ms: Option<f64>,
    /// Foreground teardown, end to end. The three spans below partition it.
    pub cleanup_handoff_ms: Option<f64>,
    /// Stopping the backend VM.
    pub stop_transient_ms: Option<f64>,
    /// Reconstructing the live backend handle during stop.
    pub stop_attach_ms: Option<f64>,
    /// Reaping host-side endpoint and service processes during stop.
    pub stop_endpoint_reaping_ms: Option<f64>,
    /// Terminating the backend VM process or driver.
    pub stop_driver_kill_ms: Option<f64>,
    /// Stopping console streaming after backend termination.
    pub stop_console_cleanup_ms: Option<f64>,
    /// Issuing the supervisor termination signal, when the backend reports it.
    pub stop_supervisor_signal_ms: Option<f64>,
    /// Waiting for the supervisor PID to disappear, when reported.
    pub stop_pid_disappearance_ms: Option<f64>,
    /// Forced termination and its follow-up wait, when reported.
    pub stop_force_kill_wait_ms: Option<f64>,
    /// Removing the backend live-process marker, when reported.
    pub stop_state_cleanup_ms: Option<f64>,
    /// Topping the warm pool back up toward its target.
    pub pool_replenish_ms: Option<f64>,
    /// Removing the VM state directories.
    pub state_remove_ms: Option<f64>,
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
            ("admit_plan", self.admit_plan_ms),
            ("attach_overlay", self.attach_overlay_ms),
            ("attach_initramfs", self.attach_initramfs_ms),
            ("vmm_create", self.vmm_create_ms),
            ("guest_kernel_entry", self.guest_kernel_entry_ms),
            ("agent_auth", self.agent_auth_ms),
            ("first_dispatch", self.first_dispatch_ms),
            ("cleanup_handoff", self.cleanup_handoff_ms),
            ("stop_transient", self.stop_transient_ms),
            ("stop_attach", self.stop_attach_ms),
            ("stop_endpoint_reaping", self.stop_endpoint_reaping_ms),
            ("stop_driver_kill", self.stop_driver_kill_ms),
            ("stop_console_cleanup", self.stop_console_cleanup_ms),
            ("stop_supervisor_signal", self.stop_supervisor_signal_ms),
            ("stop_pid_disappearance", self.stop_pid_disappearance_ms),
            ("stop_force_kill_wait", self.stop_force_kill_wait_ms),
            ("stop_state_cleanup", self.stop_state_cleanup_ms),
            ("pool_replenish", self.pool_replenish_ms),
            ("state_remove", self.state_remove_ms),
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
    /// The root filesystem path selected after the security/capability tier gate.
    #[serde(default)]
    pub root_strategy: Option<LaunchRootStrategy>,
    pub sizing: GuestSizing,
    pub artifacts: ArtifactPaths,
    pub work: LaunchWork,
    pub phases: RunPhaseTimings,
    pub sub_phases: LaunchSubTimings,
    /// Whole-VMM warm-ready resident memory and first-command fault delta.
    /// Absent for cold launches and platforms/backends without a process
    /// observation surface.
    #[serde(default)]
    pub warm_first_command_memory: Option<WarmFirstCommandMemory>,
    /// Phases the backend recorded inside its own `start`, read back from the
    /// sidecar it dropped in the VM state directory. Empty when the backend
    /// does not trace itself yet — the coarse `vmm_create` span still stands,
    /// it just cannot be broken down.
    #[serde(default)]
    pub backend_phases: Vec<TracePhase>,
    /// Capabilities the launch came up without, as the backend reported them.
    /// A non-empty list means this launch is not a sample of a healthy one.
    #[serde(default)]
    pub degraded: Vec<String>,
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
            root_strategy: Some(LaunchRootStrategy::VirtiofsRoot),
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
            warm_first_command_memory: Some(WarmFirstCommandMemory {
                pid: 42,
                ready: ProcessMemorySnapshot {
                    resident_bytes: 10,
                    minor_faults: None,
                    major_faults: None,
                },
                after_first_command: ProcessMemorySnapshot {
                    resident_bytes: 12,
                    minor_faults: None,
                    major_faults: None,
                },
                delta: ProcessMemoryDelta {
                    resident_growth_bytes: 2,
                    resident_reclaimed_bytes: 0,
                    minor_faults: None,
                    major_faults: None,
                },
            }),
            backend_phases: vec![TracePhase {
                name: "boot_confirm".to_string(),
                ms: 2.0,
            }],
            degraded: Vec::new(),
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
    fn process_memory_delta_reports_growth_faults_and_unavailable_counters() {
        let before = ProcessMemorySnapshot {
            resident_bytes: 100,
            minor_faults: Some(20),
            major_faults: None,
        };
        let after = ProcessMemorySnapshot {
            resident_bytes: 140,
            minor_faults: Some(27),
            major_faults: None,
        };
        assert_eq!(
            ProcessMemoryDelta::between(before, after),
            ProcessMemoryDelta {
                resident_growth_bytes: 40,
                resident_reclaimed_bytes: 0,
                minor_faults: Some(7),
                major_faults: None,
            }
        );
    }

    #[test]
    fn process_memory_delta_reports_reclamation_and_counter_reset_safely() {
        let before = ProcessMemorySnapshot {
            resident_bytes: 200,
            minor_faults: Some(30),
            major_faults: Some(4),
        };
        let after = ProcessMemorySnapshot {
            resident_bytes: 150,
            minor_faults: Some(2),
            major_faults: Some(6),
        };
        assert_eq!(
            ProcessMemoryDelta::between(before, after),
            ProcessMemoryDelta {
                resident_growth_bytes: 0,
                resident_reclaimed_bytes: 50,
                minor_faults: Some(0),
                major_faults: Some(2),
            }
        );
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
    fn root_strategy_mapping_preserves_the_security_tier() {
        assert_eq!(
            LaunchRootStrategy::from(mvm_build::run_image::RootStrategy::VirtiofsRoot),
            LaunchRootStrategy::VirtiofsRoot
        );
        assert_eq!(
            LaunchRootStrategy::from(mvm_build::run_image::RootStrategy::BlockExt4),
            LaunchRootStrategy::BlockExt4
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
            artifact_bytes_hashed: 0,
            process_table_scans: 0,
        };
        assert!(!contaminated.is_prepared());
        assert_eq!(
            contaminated.performed(),
            vec!["image_pull", "mount_materialize"]
        );

        // A byte count is work like any other flag, and zero is not work.
        let re_hashed = LaunchWork {
            artifact_bytes_hashed: 1_205_739_520,
            ..LaunchWork::default()
        };
        assert!(!re_hashed.is_prepared());
        assert_eq!(re_hashed.performed(), vec!["artifact_hash"]);

        let swept = LaunchWork {
            process_table_scans: 1,
            ..LaunchWork::default()
        };
        assert!(!swept.is_prepared());
        assert_eq!(swept.performed(), vec!["process_table_scan"]);
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
            stop_supervisor_signal_ms: Some(2.0),
            ..LaunchSubTimings::default()
        };
        assert_eq!(
            some.render(),
            "[mvm] phase-timing-detail: artifact_verify=0.4ms vmm_create=120.0ms cleanup_handoff=12.8ms stop_supervisor_signal=2.0ms"
        );
        assert_eq!(
            some.recorded(),
            vec![
                ("artifact_verify", 0.4),
                ("vmm_create", 120.0),
                ("cleanup_handoff", 12.75),
                ("stop_supervisor_signal", 2.0),
            ]
        );
    }

    #[test]
    fn sub_timings_accept_samples_without_new_stop_detail_fields() {
        let old = serde_json::json!({
            "stop_transient_ms": 12.5,
            "state_remove_ms": 0.6
        });
        let parsed: LaunchSubTimings = serde_json::from_value(old).expect("legacy sample");
        assert_eq!(parsed.stop_transient_ms, Some(12.5));
        assert_eq!(parsed.state_remove_ms, Some(0.6));
        assert_eq!(parsed.stop_supervisor_signal_ms, None);
        assert_eq!(parsed.stop_pid_disappearance_ms, None);
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
