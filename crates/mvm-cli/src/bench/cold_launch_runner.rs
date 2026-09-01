//! The release-only cold-launch benchmark entry point.
//!
//! It invokes a built `mvmctl` binary directly — never `cargo run` — because
//! a launch sample that includes a compile is not a launch measurement, and
//! the first such sample in a set poisons every percentile derived from it.
//! Each launch writes its own [`LaunchSample`]; this module collects those,
//! refuses any that does not belong in the lane, and summarises the rest.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result, bail};

use super::cold_launch::{
    ArtifactDigests, ArtifactMeasurements, CacheState, ColdLaunchReport, ColdLaunchSample,
    KernelConfigMeasurement, LaunchContext, LaunchLane, build_cold_launch_report,
    validate_hard_boot_requirement, validate_lane, validate_matrix_report,
};
use crate::commands::vm::launch_sample::{
    ArtifactPaths, LAUNCH_SAMPLE_ENV, LaunchRootStrategy, LaunchSample, read_sample,
};

/// Program names that would fold a build into a launch sample.
const BUILD_TOOLS: [&str; 3] = ["cargo", "rustc", "just"];

/// One lane's benchmark configuration.
///
/// Built through [`ColdLaunchBench::builder`] rather than a positional
/// constructor: the optional argument/env lists and the two run counts are
/// easy to transpose, and a transposed warm-up count silently changes what
/// the report means.
#[derive(Debug, Clone)]
pub struct ColdLaunchBench {
    mvmctl: PathBuf,
    lane: LaunchLane,
    args: Vec<String>,
    env: Vec<(String, String)>,
    runs: u32,
    warmup: u32,
    kernel_config: Option<PathBuf>,
}

/// Builder for [`ColdLaunchBench`].
#[derive(Debug, Clone)]
pub struct ColdLaunchBenchBuilder {
    mvmctl: PathBuf,
    lane: LaunchLane,
    args: Vec<String>,
    env: Vec<(String, String)>,
    runs: u32,
    warmup: u32,
    kernel_config: Option<PathBuf>,
}

impl ColdLaunchBench {
    /// Start building a lane benchmark against the binary at `mvmctl`.
    #[must_use]
    pub fn builder(mvmctl: impl Into<PathBuf>, lane: LaunchLane) -> ColdLaunchBenchBuilder {
        ColdLaunchBenchBuilder {
            mvmctl: mvmctl.into(),
            lane,
            args: Vec::new(),
            env: Vec::new(),
            runs: 20,
            warmup: 2,
            kernel_config: None,
        }
    }

    #[must_use]
    pub fn lane(&self) -> LaunchLane {
        self.lane
    }

    /// Run, validate, and return one benchmark report.
    pub fn run(&self) -> Result<ColdLaunchReport> {
        let report = self.measure()?;
        self.validate_report(&report)?;
        Ok(report)
    }

    /// Run the warm-up iterations and measured launches without applying the
    /// report-level latency gate.
    ///
    /// The CLI uses this seam so it can print and persist a failing report
    /// before returning a non-zero status. Per-sample integrity and lane
    /// validation still happen here and can never be bypassed.
    pub fn measure(&self) -> Result<ColdLaunchReport> {
        let staging = tempfile::tempdir().context("creating launch sample staging dir")?;
        let mut strategy = None;
        for index in 0..self.warmup {
            let sample = self
                .launch_once(staging.path(), "warmup", index)
                .with_context(|| format!("warm-up launch {index}"))?;
            // A warm-up that does not belong in the lane means the lane was
            // set up wrong; discarding its timing must not discard that.
            validate_lane(self.lane, &sample.launch)
                .with_context(|| format!("warm-up launch {index} does not belong in this lane"))?;
            record_root_strategy(&mut strategy, &sample.launch, "warm-up", index)?;
        }

        let mut raw = Vec::with_capacity(self.runs as usize);
        for index in 0..self.runs {
            let number = index + 1;
            let sample = self
                .launch_once(staging.path(), "measured", index)
                .with_context(|| format!("measured launch {number}"))?;
            validate_lane(self.lane, &sample.launch).with_context(|| {
                format!("measured launch {number} does not belong in this lane")
            })?;
            record_root_strategy(&mut strategy, &sample.launch, "measured", number)?;
            raw.push(cold_launch_sample(
                self.lane,
                number,
                &sample.launch,
                sample.command_lifecycle_ms,
                self.kernel_config.as_deref(),
            )?);
        }
        Ok(build_cold_launch_report(self.lane, self.warmup, raw))
    }

    /// Apply the strict hard ceiling for every report and the publication
    /// matrix gate when the configured run count reaches its sample floor.
    pub fn validate_report(&self, report: &ColdLaunchReport) -> Result<()> {
        validate_hard_boot_requirement(report)
            .context("live launch report violated the hard boot requirement")?;
        if self.runs >= super::cold_launch::MIN_MATRIX_SAMPLES {
            validate_matrix_report(report)
                .context("live launch report did not pass the matrix publication gate")?;
        }
        Ok(())
    }

    /// Spawn the binary once and read back the sample it wrote.
    fn launch_once(&self, staging: &Path, kind: &str, index: u32) -> Result<MeasuredLaunch> {
        let sample_path = staging.join(format!("{kind}-{index}.json"));
        // A stale file from a prior iteration would be read as this
        // iteration's sample if the launch died before writing.
        let _ = std::fs::remove_file(&sample_path);

        let mut command = Command::new(&self.mvmctl);
        command.args(&self.args);
        command.env(LAUNCH_SAMPLE_ENV, &sample_path);
        for (key, value) in &self.env {
            command.env(key, value);
        }
        let started = Instant::now();
        let status = command
            .status()
            .with_context(|| format!("spawning {}", self.mvmctl.display()))?;
        let command_lifecycle_ms = started.elapsed().as_secs_f64() * 1000.0;
        if !status.success() {
            bail!(
                "{} exited with {status}; a failed launch is not a measurement",
                self.mvmctl.display()
            );
        }
        Ok(MeasuredLaunch {
            launch: read_sample(&sample_path)?,
            command_lifecycle_ms,
        })
    }
}

/// One child process observed from immediately before spawn through exit.
///
/// The launch's own sample deliberately ends at transient teardown. The outer
/// wall clock also includes process creation, command-level audit completion,
/// and process shutdown, which is the latency a shell caller actually sees.
struct MeasuredLaunch {
    launch: LaunchSample,
    command_lifecycle_ms: f64,
}

fn record_root_strategy(
    expected: &mut Option<LaunchRootStrategy>,
    sample: &LaunchSample,
    phase: &str,
    number: u32,
) -> Result<()> {
    let Some(found) = sample.root_strategy else {
        bail!("{phase} launch {number} did not identify a root filesystem strategy");
    };
    match expected {
        None => *expected = Some(found),
        Some(expected) if *expected != found => {
            bail!(
                "{phase} launch {number} selected root filesystem strategy {found:?}, but the benchmark already observed {expected:?}; one report cannot mix strategies"
            );
        }
        Some(_) => {}
    }
    Ok(())
}

impl ColdLaunchBenchBuilder {
    /// Arguments passed to `mvmctl` for each launch.
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    /// Extra environment for each launch.
    #[must_use]
    pub fn env<I, K, V>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env = env.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
        self
    }

    /// Measured iterations.
    #[must_use]
    pub const fn runs(mut self, runs: u32) -> Self {
        self.runs = runs;
        self
    }

    /// Discarded iterations run before the measured set.
    #[must_use]
    pub const fn warmup(mut self, warmup: u32) -> Self {
        self.warmup = warmup;
        self
    }

    /// Optional resolved kernel config to count in each report sample.
    ///
    /// The config is read after each launch and never inside the launch
    /// process, so the measurement cannot charge config I/O to boot latency.
    #[must_use]
    pub fn kernel_config(mut self, path: impl Into<PathBuf>) -> Self {
        self.kernel_config = Some(path.into());
        self
    }

    /// Validate and build.
    pub fn build(self) -> Result<ColdLaunchBench> {
        if self.runs == 0 {
            bail!("a cold-launch benchmark needs at least one measured run");
        }
        reject_build_tool(&self.mvmctl)?;
        if !self.mvmctl.is_file() {
            bail!(
                "{} is not a file; the benchmark invokes a built binary, not a build command",
                self.mvmctl.display()
            );
        }
        Ok(ColdLaunchBench {
            mvmctl: self.mvmctl,
            lane: self.lane,
            args: self.args,
            env: self.env,
            runs: self.runs,
            warmup: self.warmup,
            kernel_config: self.kernel_config,
        })
    }
}

/// Refuse a program that builds before it runs.
///
/// The release check itself is made against the sample the binary writes,
/// which is authoritative. This is the separate failure: `cargo run` would
/// produce a perfectly valid release sample whose wall-clock includes a
/// compile, and no field in the sample can reveal that.
fn reject_build_tool(program: &Path) -> Result<()> {
    let name = program
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if BUILD_TOOLS.contains(&name.as_str()) {
        bail!(
            "refusing to benchmark through {name}: a launch sample must come from a built binary, \
             so compilation time can never enter it"
        );
    }
    Ok(())
}

/// Turn one launch's own sample into a lane sample, resolving the artifact
/// digests here — outside the measured window — so hashing never lands in a
/// launch's wall clock.
fn cold_launch_sample(
    lane: LaunchLane,
    number: u32,
    sample: &LaunchSample,
    command_lifecycle_ms: f64,
    kernel_config: Option<&Path>,
) -> Result<ColdLaunchSample> {
    Ok(ColdLaunchSample {
        lane,
        number,
        context: LaunchContext {
            backend: sample.backend.clone(),
            os: sample.os.clone(),
            arch: sample.arch.clone(),
            mvm_version: sample.mvm_version.clone(),
            vmm_version: vmm_version_for(&sample.backend, &sample.mvm_version),
            root_strategy: sample.root_strategy,
            sizing: sample.sizing,
            filesystem: host_filesystem(Path::new(&mvm_core::config::mvm_home())),
            artifacts: sample.artifacts.clone(),
            digests: digests_for(&sample.artifacts),
            measurements: measurements_for(&sample.artifacts, kernel_config)?,
        },
        cache: CacheState::from_sample(sample),
        work: sample.work,
        launch_mode: sample.launch_mode,
        command_lifecycle_ms,
        phases: sample.phases,
        sub_phases: sample.sub_phases,
        warm_first_command_memory: sample.warm_first_command_memory,
        backend_phases: sample.backend_phases.clone(),
        degraded: sample.degraded.clone(),
    })
}

fn measurements_for(
    paths: &ArtifactPaths,
    kernel_config: Option<&Path>,
) -> Result<ArtifactMeasurements> {
    let bytes = |path: &Option<String>| {
        path.as_deref()
            .and_then(|path| std::fs::metadata(path).ok())
            .filter(|metadata| metadata.is_file())
            .map(|metadata| metadata.len())
    };
    let kernel_config = kernel_config
        .map(read_kernel_config_measurement)
        .transpose()?;
    Ok(ArtifactMeasurements {
        kernel_bytes: bytes(&paths.kernel),
        initramfs_bytes: bytes(&paths.initramfs),
        runtime_overlay_bytes: bytes(&paths.runtime_overlay),
        rootfs_bytes: bytes(&paths.rootfs),
        kernel_config,
    })
}

fn read_kernel_config_measurement(path: &Path) -> Result<KernelConfigMeasurement> {
    let config = std::fs::read_to_string(path)
        .with_context(|| format!("reading kernel config {}", path.display()))?;
    let builtin_symbols = config
        .lines()
        .filter(|line| line.trim_end().ends_with("=y"))
        .count();
    Ok(KernelConfigMeasurement {
        path: path.display().to_string(),
        builtin_symbols: u32::try_from(builtin_symbols).unwrap_or(u32::MAX),
    })
}

/// The VMM's version, where it is knowable without probing a foreign binary.
///
/// The in-house VMM is compiled into `mvmctl`, so its version is `mvmctl`'s.
/// A third-party VMM's version is not resolved here; `None` records "not
/// resolved" rather than inventing a number that would silently make two
/// incomparable baselines look comparable.
fn vmm_version_for(backend: &str, mvm_version: &str) -> Option<String> {
    match backend {
        "hvf" => Some(mvm_version.to_string()),
        _ => None,
    }
}

fn digests_for(paths: &ArtifactPaths) -> ArtifactDigests {
    let digest = |path: &Option<String>| {
        path.as_ref()
            .and_then(|p| mvm_core::crypto::image_verify::sha256_file(Path::new(p)).ok())
    };
    ArtifactDigests {
        kernel_sha256: digest(&paths.kernel),
        initramfs_sha256: digest(&paths.initramfs),
        runtime_overlay_sha256: digest(&paths.runtime_overlay),
        rootfs_sha256: digest(&paths.rootfs),
    }
}

/// Filesystem type backing `path`, so a baseline taken on one filesystem is
/// not compared against one taken on another.
#[cfg(target_os = "linux")]
fn host_filesystem(path: &Path) -> Option<String> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    filesystem_from_proc_mounts(&mounts, path)
}

/// Longest mount-point prefix of `path` in a `/proc/mounts` body.
#[cfg(any(test, target_os = "linux"))]
fn filesystem_from_proc_mounts(mounts: &str, path: &Path) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let _device = fields.next()?;
        let Some(mount_point) = fields.next() else {
            continue;
        };
        let Some(fs_type) = fields.next() else {
            continue;
        };
        if !path.starts_with(mount_point) {
            continue;
        }
        let depth = mount_point.len();
        if best.as_ref().is_none_or(|(seen, _)| depth > *seen) {
            best = Some((depth, fs_type.to_string()));
        }
    }
    best.map(|(_, fs_type)| fs_type)
}

#[cfg(target_os = "macos")]
fn host_filesystem(path: &Path) -> Option<String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `c_path` is a NUL-terminated C string that outlives the call,
    // and `buf` is a correctly sized, aligned, zeroed `statfs` this thread
    // exclusively owns. `statfs` only writes through the out pointer, and the
    // result is read solely on the success return.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: `statfs` returned 0, so it initialised the whole struct.
    let stat = unsafe { buf.assume_init() };
    let name: Vec<u8> = stat
        .f_fstypename
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    String::from_utf8(name).ok()
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
fn host_filesystem(_path: &Path) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vm::launch_sample::{
        BuildProfile, GuestSizing, LAUNCH_SAMPLE_SCHEMA_VERSION, LaunchRootStrategy,
        LaunchSubTimings, LaunchWork, ProcessMemoryDelta, ProcessMemorySnapshot,
        WarmFirstCommandMemory, write_sample,
    };
    use crate::commands::vm::phase_timing::{LaunchMode, RunPhaseTimings};

    fn sample_for(total_ms: f64) -> LaunchSample {
        LaunchSample {
            schema_version: LAUNCH_SAMPLE_SCHEMA_VERSION,
            build_profile: BuildProfile::Release,
            mvm_version: "9.9.9".to_string(),
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
            phases: RunPhaseTimings {
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
            },
            sub_phases: LaunchSubTimings {
                vmm_create_ms: Some(90.0),
                ..LaunchSubTimings::default()
            },
            warm_first_command_memory: None,
            backend_phases: Vec::new(),
            degraded: Vec::new(),
        }
    }

    #[test]
    fn a_build_tool_is_refused_as_the_benchmark_program() {
        for program in ["/usr/bin/cargo", "/opt/rustc", "/usr/local/bin/just"] {
            let err = reject_build_tool(Path::new(program)).unwrap_err();
            assert!(
                err.to_string().contains("built binary"),
                "unexpected error for {program}: {err:#}"
            );
        }
        assert!(reject_build_tool(Path::new("/x/target/release/mvmctl")).is_ok());
    }

    #[test]
    fn builder_refuses_a_missing_binary_and_a_zero_run_count() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("mvmctl");
        let err = ColdLaunchBench::builder(&missing, LaunchLane::PreparedCold)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("not a file"), "{err:#}");

        std::fs::write(&missing, b"#!/bin/sh\n").unwrap();
        let err = ColdLaunchBench::builder(&missing, LaunchLane::PreparedCold)
            .runs(0)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("at least one"), "{err:#}");
    }

    #[test]
    fn builder_refuses_cargo_before_touching_the_filesystem() {
        let err = ColdLaunchBench::builder("cargo", LaunchLane::PreparedCold)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("refusing to benchmark"), "{err:#}");
    }

    #[test]
    fn vmm_version_is_resolved_only_where_it_is_known() {
        assert_eq!(vmm_version_for("hvf", "1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(vmm_version_for("libkrun", "1.2.3"), None);
        assert_eq!(vmm_version_for("firecracker", "1.2.3"), None);
    }

    #[test]
    fn digests_are_resolved_from_the_artifact_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        std::fs::write(&kernel, b"kernel-bytes").unwrap();
        let digests = digests_for(&ArtifactPaths {
            kernel: Some(kernel.to_string_lossy().into_owned()),
            initramfs: Some(tmp.path().join("absent").to_string_lossy().into_owned()),
            runtime_overlay: None,
            rootfs: None,
        });
        assert_eq!(
            digests.kernel_sha256,
            mvm_core::crypto::image_verify::sha256_file(&kernel).ok()
        );
        // An unreadable path is recorded as unresolved, not as an error that
        // aborts a whole measured set.
        assert_eq!(digests.initramfs_sha256, None);
        assert_eq!(digests.runtime_overlay_sha256, None);
    }

    #[test]
    fn measurements_capture_artifact_bytes_and_kernel_config_symbols() {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = tmp.path().join("vmlinux");
        let initramfs = tmp.path().join("initramfs.cpio.gz");
        let config = tmp.path().join("workload.config");
        std::fs::write(&kernel, b"kernel").unwrap();
        std::fs::write(&initramfs, b"initrd").unwrap();
        std::fs::write(&config, "CONFIG_ONE=y\nCONFIG_TWO=m\nCONFIG_THREE=y\n").unwrap();

        let measurements = measurements_for(
            &ArtifactPaths {
                kernel: Some(kernel.to_string_lossy().into_owned()),
                initramfs: Some(initramfs.to_string_lossy().into_owned()),
                runtime_overlay: None,
                rootfs: None,
            },
            Some(&config),
        )
        .unwrap();

        assert_eq!(measurements.kernel_bytes, Some(6));
        assert_eq!(measurements.initramfs_bytes, Some(6));
        assert_eq!(measurements.runtime_overlay_bytes, None);
        assert_eq!(measurements.rootfs_bytes, None);
        assert_eq!(
            measurements.kernel_config,
            Some(KernelConfigMeasurement {
                path: config.display().to_string(),
                builtin_symbols: 2,
            })
        );
    }

    #[test]
    fn proc_mounts_picks_the_longest_matching_mount_point() {
        let mounts = "\
/dev/root / ext4 rw,relatime 0 0
tmpfs /tmp tmpfs rw 0 0
/dev/sdb1 /home/user xfs rw 0 0
";
        assert_eq!(
            filesystem_from_proc_mounts(mounts, Path::new("/home/user/state")),
            Some("xfs".to_string())
        );
        assert_eq!(
            filesystem_from_proc_mounts(mounts, Path::new("/var/lib")),
            Some("ext4".to_string())
        );
        assert_eq!(filesystem_from_proc_mounts("", Path::new("/")), None);
    }

    #[test]
    fn a_sample_becomes_a_lane_sample_with_derived_context() {
        let sample = sample_for(148.0);
        let lane_sample =
            cold_launch_sample(LaunchLane::PreparedCold, 3, &sample, 175.0, None).unwrap();
        assert_eq!(lane_sample.number, 3);
        assert_eq!(lane_sample.context.backend, "hvf");
        assert_eq!(
            lane_sample.context.vmm_version,
            Some("9.9.9".to_string()),
            "the in-house VMM ships inside mvmctl, so its version is known"
        );
        assert_eq!(
            lane_sample.context.root_strategy,
            Some(LaunchRootStrategy::BlockExt4)
        );
        assert!(lane_sample.cache.artifacts_cached);
        assert_eq!(lane_sample.command_lifecycle_ms, 175.0);
        assert_eq!(lane_sample.phases.total_ms, 148.0);
        assert_eq!(lane_sample.sub_phases.vmm_create_ms, Some(90.0));
    }

    #[test]
    fn lane_sample_preserves_warm_memory_evidence() {
        let mut sample = sample_for(148.0);
        let ready = ProcessMemorySnapshot {
            resident_bytes: 100,
            minor_faults: Some(3),
            major_faults: Some(1),
        };
        let after_first_command = ProcessMemorySnapshot {
            resident_bytes: 120,
            minor_faults: Some(8),
            major_faults: Some(1),
        };
        let measurement = WarmFirstCommandMemory {
            pid: 42,
            ready,
            after_first_command,
            delta: ProcessMemoryDelta::between(ready, after_first_command),
        };
        sample.warm_first_command_memory = Some(measurement);

        let lane_sample =
            cold_launch_sample(LaunchLane::WarmClaim, 1, &sample, 175.0, None).unwrap();
        assert_eq!(lane_sample.warm_first_command_memory, Some(measurement));
    }

    /// A stand-in `mvmctl` that writes the sample its argument names. It
    /// proves the spawn/collect/validate loop without a hypervisor: the
    /// contract between the runner and the launching binary is the sample
    /// file, so a binary that writes one is a faithful counterparty.
    #[cfg(unix)]
    fn fake_mvmctl(dir: &Path, samples: &[LaunchSample]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let bodies: Vec<String> = samples
            .iter()
            .map(|sample| serde_json::to_string(sample).unwrap())
            .collect();
        let counter = dir.join("count");
        std::fs::write(&counter, "0").unwrap();

        let mut script = String::from("#!/bin/sh\nset -e\n");
        script.push_str(&format!("n=$(cat {})\n", counter.display()));
        script.push_str(&format!("echo $((n + 1)) > {}\n", counter.display()));
        for (index, body) in bodies.iter().enumerate() {
            script.push_str(&format!(
                "if [ \"$n\" -eq {index} ]; then printf '%s' '{body}' > \"$MVM_LAUNCH_SAMPLE_JSON\"; exit 0; fi\n"
            ));
        }
        script.push_str(&format!(
            "printf '%s' '{}' > \"$MVM_LAUNCH_SAMPLE_JSON\"\n",
            bodies.last().expect("at least one sample")
        ));

        let path = dir.join("mvmctl");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn the_runner_discards_warmups_and_summarises_measured_launches() {
        let tmp = tempfile::tempdir().unwrap();
        // Two warm-ups then four measured launches, each slower than the last
        // so the percentiles are checkable.
        let samples: Vec<LaunchSample> = [500.0, 400.0, 100.0, 200.0, 300.0, 400.0]
            .into_iter()
            .map(sample_for)
            .collect();
        let mvmctl = fake_mvmctl(tmp.path(), &samples);

        let report = ColdLaunchBench::builder(&mvmctl, LaunchLane::PreparedCold)
            .runs(4)
            .warmup(2)
            .build()
            .unwrap()
            .run()
            .unwrap();

        assert_eq!(report.raw.len(), 4, "warm-ups must not be reported");
        assert_eq!(report.warmup, 2);
        assert_eq!(
            report.raw.iter().map(|s| s.number).collect::<Vec<u32>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(report.stats.total_ms.p50, Some(250.0));
        assert_eq!(report.stats.command_lifecycle_ms.samples, 4);
        assert!(
            report
                .stats
                .command_lifecycle_ms
                .p50
                .is_some_and(|ms| ms > 0.0),
            "the shell-visible process lifetime must be measured"
        );
        let vmm_create = report
            .stats
            .sub_phases
            .iter()
            .find(|(name, _)| name == "vmm_create")
            .map(|(_, stats)| *stats)
            .expect("vmm_create is always reported");
        assert_eq!(vmm_create.samples, 4);
    }

    #[cfg(unix)]
    #[test]
    fn measurement_is_available_before_the_hard_gate_returns_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let mut sample = sample_for(220.0);
        sample.phases.backend_start_ms = 170.0;
        sample.phases.vsock_wait_ms = 30.0;
        let mvmctl = fake_mvmctl(tmp.path(), &[sample]);
        let bench = ColdLaunchBench::builder(&mvmctl, LaunchLane::PreparedCold)
            .runs(1)
            .warmup(0)
            .build()
            .unwrap();

        let report = bench.measure().expect("measurement remains reportable");
        assert_eq!(report.stats.dispatch_window_ms.max, Some(200.0));
        let err = bench
            .validate_report(&report)
            .expect_err("the exact boundary must fail");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("hard boot requirement"), "{rendered}");
        assert!(rendered.contains("under 200.0ms"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn the_runner_refuses_a_contaminated_measured_launch() {
        let tmp = tempfile::tempdir().unwrap();
        let mut contaminated = sample_for(100.0);
        contaminated.work.image_pull = true;
        let mvmctl = fake_mvmctl(tmp.path(), &[sample_for(100.0), contaminated]);

        let err = ColdLaunchBench::builder(&mvmctl, LaunchLane::PreparedCold)
            .runs(2)
            .warmup(0)
            .build()
            .unwrap()
            .run()
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("measured launch 2"), "{rendered}");
        assert!(rendered.contains("image_pull"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn the_runner_refuses_mixed_root_filesystem_strategies() {
        let tmp = tempfile::tempdir().unwrap();
        let mut different = sample_for(100.0);
        different.root_strategy = None;
        let mvmctl = fake_mvmctl(tmp.path(), &[sample_for(100.0), different]);

        let err = ColdLaunchBench::builder(&mvmctl, LaunchLane::PreparedCold)
            .runs(2)
            .warmup(0)
            .build()
            .unwrap()
            .run()
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("root filesystem strategy"), "{rendered}");
        assert!(rendered.contains("measured launch 2"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn the_runner_refuses_a_debug_build_at_the_first_warm_up() {
        let tmp = tempfile::tempdir().unwrap();
        let mut debug_sample = sample_for(100.0);
        debug_sample.build_profile = BuildProfile::Debug;
        let mvmctl = fake_mvmctl(tmp.path(), &[debug_sample]);

        let err = ColdLaunchBench::builder(&mvmctl, LaunchLane::PreparedCold)
            .runs(1)
            .warmup(1)
            .build()
            .unwrap()
            .run()
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("warm-up launch 0"), "{rendered}");
        assert!(rendered.contains("release-only"), "{rendered}");
    }

    #[cfg(unix)]
    #[test]
    fn a_launch_that_writes_no_sample_is_an_error_not_a_stale_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mvmctl");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let err = ColdLaunchBench::builder(&path, LaunchLane::PreparedCold)
            .runs(1)
            .warmup(0)
            .build()
            .unwrap()
            .run()
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("reading launch sample"),
            "{err:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_launch_is_not_a_measurement() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mvmctl");
        let sample_json = serde_json::to_string(&sample_for(100.0)).unwrap();
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s' '{sample_json}' > \"$MVM_LAUNCH_SAMPLE_JSON\"\nexit 3\n"
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let err = ColdLaunchBench::builder(&path, LaunchLane::PreparedCold)
            .runs(1)
            .warmup(0)
            .build()
            .unwrap()
            .run()
            .unwrap_err();
        assert!(format!("{err:#}").contains("exited with"), "{err:#}");
    }

    #[test]
    fn write_sample_and_read_sample_are_the_runner_contract() {
        // The runner reads exactly what a launch writes; pin that here so a
        // schema change breaks one obvious test rather than the live lane.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sample.json");
        write_sample(&path, &sample_for(42.0)).unwrap();
        assert_eq!(read_sample(&path).unwrap(), sample_for(42.0));
    }
}
