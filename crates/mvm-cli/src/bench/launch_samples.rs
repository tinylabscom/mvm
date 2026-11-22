//! Cold-launch latency from the launch samples a density run takes.
//!
//! The density waves launch resident guests, which never finish and so never
//! write a launch sample. The harness therefore takes a short series of cold
//! launches of a command that exits, beside the waves, into
//! `launch-samples/`. This module folds that series into a section's latency
//! rows, with the time spent hashing artifacts reported apart from the rest of
//! the launch so the two are never one figure.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::cold_launch::SpanStats;
use super::resource_report::{Figure, Section, supported};
use crate::commands::vm::launch_sample::{
    BuildProfile, LAUNCH_SAMPLE_SCHEMA_VERSION, LaunchSample,
};
use crate::commands::vm::phase_timing::LaunchMode;

/// Directory of the density run that holds the samples.
pub const SAMPLE_DIR: &str = "launch-samples";

/// What the harness recorded in `summary.tsv` under `launch_samples`.
pub const STATUS_KEY: &str = "launch_samples";

/// The harness's word for "samples are on disk".
pub const STATUS_TAKEN: &str = "taken";

/// One launch, split into the part spent hashing and the rest.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Split {
    startup_ms: f64,
    hash_ms: f64,
}

impl Split {
    /// Everything but hashing. Clamped, because hashing the launch did after the
    /// guest was reachable is not part of the startup it is subtracted from.
    fn boot_ms(self) -> f64 {
        (self.startup_ms - self.hash_ms).max(0.0)
    }
}

fn split_of(sample: &LaunchSample, section: &Section) -> Result<Split> {
    if sample.schema_version != LAUNCH_SAMPLE_SCHEMA_VERSION {
        bail!(
            "launch sample schema {} is not {LAUNCH_SAMPLE_SCHEMA_VERSION}",
            sample.schema_version
        );
    }
    if sample.build_profile != BuildProfile::Release {
        bail!("a launch sample from a debug build measures the profile, not the launch");
    }
    if sample.launch_mode != LaunchMode::Cold {
        bail!("a launch sample for the cold rows was not a cold launch");
    }
    if !sample.degraded.is_empty() {
        bail!(
            "a launch sample came up without {}; it is not a healthy launch",
            sample.degraded.join(", ")
        );
    }
    if sample.backend != section.backend || sample.arch != section.architecture {
        bail!(
            "a launch sample ran on {}/{}, the density run on {}/{}",
            sample.backend,
            sample.arch,
            section.backend,
            section.architecture
        );
    }
    let startup_ms = sample
        .phases
        .startup_ms
        .context("a launch sample records no startup span")?;
    Ok(Split {
        startup_ms,
        hash_ms: sample.work.artifact_hash_us as f64 / 1000.0,
    })
}

fn read_samples(dir: &Path) -> Result<Vec<LaunchSample>> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&text)
                .with_context(|| format!("{} is not a launch sample", path.display()))
        })
        .collect()
}

/// Fold the launch samples of a run directory into `section`. `status` is what
/// the harness recorded: anything but [`STATUS_TAKEN`] is a reason the run has
/// no samples, and becomes the unmeasured reason as written.
pub fn fold_launch_samples(
    section: &mut Section,
    run_dir: &Path,
    status: Option<&str>,
) -> Result<()> {
    let reason = match status {
        Some(STATUS_TAKEN) => None,
        Some(other) => Some(other.to_owned()),
        None => Some("the run recorded no launch samples; it predates them".to_owned()),
    };
    if let Some(reason) = reason {
        let l = &mut section.latencies;
        for figure in [
            &mut l.cold_launch_startup_ms,
            &mut l.cold_launch_artifact_hash_ms,
            &mut l.cold_launch_boot_ms,
        ] {
            *figure = Figure::unmeasured(reason.clone());
        }
        return Ok(());
    }
    let samples = read_samples(&run_dir.join(SAMPLE_DIR))?;
    if samples.is_empty() {
        bail!("the run says it took launch samples but {SAMPLE_DIR}/ holds none");
    }
    let splits = samples
        .iter()
        .map(|sample| split_of(sample, section))
        .collect::<Result<Vec<_>>>()?;
    let stats = |value: fn(&Split) -> f64| {
        Figure::measured(supported(SpanStats::from_samples(
            &splits.iter().map(value).collect::<Vec<_>>(),
        )))
    };
    let l = &mut section.latencies;
    l.cold_launch_startup_ms = stats(|s| s.startup_ms);
    l.cold_launch_artifact_hash_ms = stats(|s| s.hash_ms);
    l.cold_launch_boot_ms = stats(|s| s.boot_ms());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::resource_report::WakeupQuantity;

    fn section() -> Section {
        Section::unmeasured("firecracker", "x86_64", WakeupQuantity::LinuxProcfs)
    }

    fn sample(startup_ms: f64, hash_us: u64) -> LaunchSample {
        let mut sample: LaunchSample = serde_json::from_value(serde_json::json!({
            "schema_version": LAUNCH_SAMPLE_SCHEMA_VERSION,
            "build_profile": "release",
            "mvm_version": "0",
            "backend": "firecracker",
            "os": "linux",
            "arch": "x86_64",
            "launch_mode": "cold",
            "sizing": {"cpus": 2, "memory_mib": 512},
            "artifacts": {},
            "work": {},
            "phases": {
                "launch_mode": "cold", "resolve_ms": 1.0, "drives_ms": 1.0,
                "admit_ms": 1.0, "pool_wait_ms": 0.0, "claim_ms": 0.0,
                "backend_start_ms": 1.0, "vsock_wait_ms": 1.0,
                "warm_window_ms": 0.0, "command_ms": 1.0, "teardown_ms": 1.0,
                "total_ms": 7.0
            },
            "sub_phases": {}
        }))
        .unwrap();
        sample.phases.startup_ms = Some(startup_ms);
        sample.work.artifact_hash_us = hash_us;
        sample
    }

    fn write_run(samples: &[LaunchSample]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(SAMPLE_DIR);
        std::fs::create_dir(&dir).unwrap();
        for (i, s) in samples.iter().enumerate() {
            let text = serde_json::to_string(s).unwrap();
            std::fs::write(dir.join(format!("{i:03}.sample.json")), text).unwrap();
        }
        tmp
    }

    fn stats(f: &Figure<SpanStats>) -> SpanStats {
        *f.value().expect("figure should be measured")
    }

    #[test]
    fn hashing_is_reported_apart_from_the_rest_of_the_launch() {
        let run = write_run(&[sample(1000.0, 400_000), sample(2000.0, 600_000)]);
        let mut s = section();
        fold_launch_samples(&mut s, run.path(), Some(STATUS_TAKEN)).unwrap();
        let l = &s.latencies;
        assert_eq!(stats(&l.cold_launch_startup_ms).max, Some(2000.0));
        assert_eq!(stats(&l.cold_launch_artifact_hash_ms).max, Some(600.0));
        assert_eq!(stats(&l.cold_launch_boot_ms).max, Some(1400.0));
    }

    #[test]
    fn hashing_after_the_guest_was_reachable_cannot_make_boot_negative() {
        let split = Split {
            startup_ms: 100.0,
            hash_ms: 250.0,
        };
        assert_eq!(split.boot_ms(), 0.0);
    }

    #[test]
    fn two_samples_name_a_count_and_no_tail_percentile() {
        let run = write_run(&[sample(1000.0, 0), sample(2000.0, 0)]);
        let mut s = section();
        fold_launch_samples(&mut s, run.path(), Some(STATUS_TAKEN)).unwrap();
        let startup = stats(&s.latencies.cold_launch_startup_ms);
        assert_eq!(startup.samples, 2);
        assert!(startup.p50.is_some());
        assert_eq!((startup.p95, startup.p99), (None, None));
    }

    #[test]
    fn a_recorded_reason_is_the_unmeasured_reason() {
        let mut s = section();
        fold_launch_samples(&mut s, Path::new("/nonexistent"), Some("unavailable:boom")).unwrap();
        assert_eq!(
            s.latencies.cold_launch_boot_ms,
            Figure::unmeasured("unavailable:boom")
        );
    }

    #[test]
    fn a_run_without_the_record_says_it_predates_samples() {
        let mut s = section();
        fold_launch_samples(&mut s, Path::new("/nonexistent"), None).unwrap();
        let reason = format!("{:?}", s.latencies.cold_launch_startup_ms);
        assert!(reason.contains("predates"));
    }

    #[test]
    fn missing_malformed_and_wrong_host_samples_are_refused() {
        let mut s = section();
        // Said taken, no directory.
        let empty = tempfile::tempdir().unwrap();
        assert!(fold_launch_samples(&mut s, empty.path(), Some(STATUS_TAKEN)).is_err());
        // Said taken, directory empty.
        std::fs::create_dir(empty.path().join(SAMPLE_DIR)).unwrap();
        assert!(fold_launch_samples(&mut s, empty.path(), Some(STATUS_TAKEN)).is_err());
        // Malformed.
        std::fs::write(empty.path().join(SAMPLE_DIR).join("a.sample.json"), "{").unwrap();
        assert!(fold_launch_samples(&mut s, empty.path(), Some(STATUS_TAKEN)).is_err());
        // Another backend.
        let mut other = sample(1.0, 0);
        other.backend = "hvf".into();
        let run = write_run(&[other]);
        assert!(fold_launch_samples(&mut s, run.path(), Some(STATUS_TAKEN)).is_err());
        // Warm, degraded, no startup span.
        for edit in [
            (|x: &mut LaunchSample| x.launch_mode = LaunchMode::Warm) as fn(&mut LaunchSample),
            |x| x.degraded = vec!["host_services".into()],
            |x| x.phases.startup_ms = None,
        ] {
            let mut bad = sample(1.0, 0);
            edit(&mut bad);
            let run = write_run(&[bad]);
            assert!(fold_launch_samples(&mut s, run.path(), Some(STATUS_TAKEN)).is_err());
        }
        assert_eq!(s.latencies.cold_launch_startup_ms, Figure::default());
    }
}
