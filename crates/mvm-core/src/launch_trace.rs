//! Backend-recorded launch phases, dropped beside the VM's other state so the
//! caller can read them once `start` returns.
//!
//! A backend launch crosses a process boundary: the caller assembles a
//! configuration, spawns a supervisor, and then waits for that supervisor to
//! confirm boot. From outside, all of it is one opaque span, which is exactly
//! the span worth breaking up. Rather than widen the `VmBackend` trait for a
//! diagnostic, a backend drops a sidecar next to `console.log` and the caller
//! folds it into its own launch sample.
//!
//! Phase names are backend-defined strings rather than a shared enum on
//! purpose. The phases a Hypervisor.framework launch goes through are not the
//! phases a Firecracker launch goes through, and a common enum would either
//! become the union of every backend's internals or force each backend to
//! report a phase it never ran.
//!
//! Recording is off unless a launch measurement asked for it, and every write
//! is best-effort: a diagnostic that can fail a launch is worse than no
//! diagnostic.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Sidecar filename inside the VM state directory.
pub const LAUNCH_TRACE_FILE: &str = "launch-trace.json";

/// Set to `1`/`true` to print a per-phase launch breakdown to stderr.
pub const PHASE_TIMING_ENV: &str = "MVM_PHASE_TIMING";

/// Names the file a launch writes its machine-readable sample to.
pub const LAUNCH_SAMPLE_ENV: &str = "MVM_LAUNCH_SAMPLE_JSON";

/// One named span inside a backend's `start`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TracePhase {
    pub name: String,
    pub ms: f64,
}

/// Every phase one backend launch recorded, in the order they ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendLaunchTrace {
    pub backend: String,
    pub phases: Vec<TracePhase>,
    /// Capabilities the launch came up without.
    ///
    /// A launch can succeed with a best-effort subsystem unregistered, which
    /// makes it a poor sample of a healthy launch and, worse, a silent loss of
    /// something a caller believed it had. Naming it here is what lets a
    /// consumer refuse the sample instead of averaging it in.
    #[serde(default)]
    pub degraded: Vec<String>,
}

impl BackendLaunchTrace {
    /// The recorded duration of one phase, if the launch ran it.
    #[must_use]
    pub fn phase_ms(&self, name: &str) -> Option<f64> {
        self.phases
            .iter()
            .find(|phase| phase.name == name)
            .map(|phase| phase.ms)
    }

    /// Sum of every recorded phase. The phases partition `start`, so this
    /// should track the caller's own span for the same call; a large gap means
    /// a phase is unmarked.
    #[must_use]
    pub fn total_ms(&self) -> f64 {
        self.phases.iter().map(|phase| phase.ms).sum()
    }
}

/// Whether a launch should record its phases, pure over the two raw env
/// values so the gate is testable without mutating process env.
#[must_use]
pub fn tracing_enabled_from(phase_timing: Option<&str>, sample_path: Option<&str>) -> bool {
    let truthy = matches!(phase_timing, Some(v) if v == "1" || v.eq_ignore_ascii_case("true"));
    let sampling = matches!(sample_path, Some(v) if !v.trim().is_empty());
    truthy || sampling
}

/// Read the environment and decide whether to record.
#[must_use]
pub fn tracing_enabled() -> bool {
    tracing_enabled_from(
        std::env::var(PHASE_TIMING_ENV).ok().as_deref(),
        std::env::var(LAUNCH_SAMPLE_ENV).ok().as_deref(),
    )
}

/// Records successive phases of one backend launch.
///
/// Each [`mark`](Self::mark) closes the span that began at the previous mark
/// (or at construction), so a backend names phases as it passes them rather
/// than bracketing each one.
#[derive(Debug)]
pub struct LaunchTraceRecorder {
    backend: String,
    enabled: bool,
    last: Instant,
    phases: Vec<TracePhase>,
    degraded: Vec<String>,
}

impl LaunchTraceRecorder {
    /// A recorder for `backend`, inert unless a measurement asked for one.
    #[must_use]
    pub fn new(backend: &str) -> Self {
        Self::with_enabled(backend, tracing_enabled())
    }

    /// Construct with an explicit gate — the seam the tests drive.
    #[must_use]
    pub fn with_enabled(backend: &str, enabled: bool) -> Self {
        Self {
            backend: backend.to_string(),
            enabled,
            last: Instant::now(),
            phases: Vec::new(),
            degraded: Vec::new(),
        }
    }

    /// Record that `what` is unavailable for this launch unless `healthy`.
    ///
    /// Phrased as the negative because the caller holds the health signal and
    /// the interesting case is the one that is easy to drop on the floor.
    pub fn degrade_unless(&mut self, what: &'static str, healthy: bool) {
        if self.enabled && !healthy {
            self.degraded.push(what.to_string());
        }
    }

    /// Close the current span and name it.
    pub fn mark(&mut self, name: &'static str) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        self.phases.push(TracePhase {
            name: name.to_string(),
            ms: now.saturating_duration_since(self.last).as_secs_f64() * 1000.0,
        });
        self.last = now;
    }

    /// The trace so far, or `None` when recording is off.
    #[must_use]
    pub fn finish(self) -> Option<BackendLaunchTrace> {
        if !self.enabled {
            return None;
        }
        Some(BackendLaunchTrace {
            backend: self.backend,
            phases: self.phases,
            degraded: self.degraded,
        })
    }

    /// Write the trace into `state_dir`. Best-effort: a launch must never fail
    /// because its diagnostic could not be written.
    pub fn write_to(self, state_dir: &Path) {
        let Some(trace) = self.finish() else {
            return;
        };
        if let Ok(json) = serde_json::to_string_pretty(&trace) {
            let _ = std::fs::write(trace_path(state_dir), json);
        }
    }
}

/// Expensive acquisition work a launch performed, recorded process-wide.
///
/// The registry fetch and the guest/image builds sit in crates far below the
/// one that reports the sample, and threading a flag back through every layer
/// between them would be a wide refactor in service of a diagnostic. Two
/// atomics, set once and never cleared, keep the report honest instead. Set
/// once means a sample can only over-report work, never under-report it, which
/// is the safe direction for a gate that refuses contaminated samples.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcquisitionWork {
    pub image_pull: bool,
    pub image_build: bool,
}

struct AcquisitionRecorder {
    image_pull: AtomicBool,
    image_build: AtomicBool,
}

static ACQUISITION: AcquisitionRecorder = AcquisitionRecorder {
    image_pull: AtomicBool::new(false),
    image_build: AtomicBool::new(false),
};

/// Record that this process fetched image bytes from a registry.
pub fn record_image_pull() {
    ACQUISITION.image_pull.store(true, Ordering::Relaxed);
}

/// Record that this process built an image or a guest artifact.
pub fn record_image_build() {
    ACQUISITION.image_build.store(true, Ordering::Relaxed);
}

/// What acquisition work this process has performed so far.
#[must_use]
pub fn recorded_acquisition() -> AcquisitionWork {
    AcquisitionWork {
        image_pull: ACQUISITION.image_pull.load(Ordering::Relaxed),
        image_build: ACQUISITION.image_build.load(Ordering::Relaxed),
    }
}

/// Where a VM's trace sidecar lives.
#[must_use]
pub fn trace_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LAUNCH_TRACE_FILE)
}

/// Read a launch trace a backend wrote. A missing or unparsable sidecar reads
/// as `None` — the launch still happened, it just was not traced.
#[must_use]
pub fn read_trace(state_dir: &Path) -> Option<BackendLaunchTrace> {
    let bytes = std::fs::read(trace_path(state_dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_disabled_recorder_records_nothing() {
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", false);
        rec.mark("preflight");
        rec.mark("boot_confirm");
        assert!(rec.finish().is_none());
    }

    #[test]
    fn marks_become_ordered_named_spans() {
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", true);
        std::thread::sleep(Duration::from_millis(15));
        rec.mark("preflight");
        rec.mark("boot_confirm");
        let trace = rec.finish().expect("enabled recorder yields a trace");

        assert_eq!(trace.backend, "hvf");
        assert_eq!(
            trace
                .phases
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<&str>>(),
            vec!["preflight", "boot_confirm"]
        );
        let preflight = trace.phase_ms("preflight").expect("preflight recorded");
        assert!(preflight >= 15.0, "preflight measured {preflight}ms");
        // The second mark closes a span that began at the first, so it does not
        // re-count the sleep.
        let confirm = trace
            .phase_ms("boot_confirm")
            .expect("boot_confirm recorded");
        assert!(
            confirm < preflight,
            "spans must not overlap: {confirm} vs {preflight}"
        );
        assert!((trace.total_ms() - (preflight + confirm)).abs() < 1e-9);
    }

    #[test]
    fn an_unrecorded_phase_reads_as_absent() {
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", true);
        rec.mark("preflight");
        let trace = rec.finish().unwrap();
        assert_eq!(trace.phase_ms("boot_confirm"), None);
    }

    #[test]
    fn trace_round_trips_through_the_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", true);
        rec.mark("preflight");
        rec.mark("boot_confirm");
        let expected = {
            let mut copy = LaunchTraceRecorder::with_enabled("hvf", true);
            copy.phases = rec.phases.clone();
            copy.degraded = rec.degraded.clone();
            copy.finish().unwrap()
        };
        rec.write_to(tmp.path());
        assert_eq!(read_trace(tmp.path()), Some(expected));
    }

    #[test]
    fn a_disabled_recorder_writes_no_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", false);
        rec.mark("preflight");
        rec.write_to(tmp.path());
        assert_eq!(read_trace(tmp.path()), None);
        assert!(!trace_path(tmp.path()).exists());
    }

    #[test]
    fn a_missing_or_corrupt_sidecar_reads_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(read_trace(tmp.path()), None);
        std::fs::write(trace_path(tmp.path()), b"{not json").unwrap();
        assert_eq!(read_trace(tmp.path()), None);
    }

    #[test]
    fn writing_into_a_missing_directory_does_not_panic() {
        // The state dir is created before a launch, but a diagnostic must not
        // be the thing that panics if it ever is not.
        let tmp = tempfile::tempdir().unwrap();
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", true);
        rec.mark("preflight");
        rec.write_to(&tmp.path().join("absent"));
    }

    #[test]
    fn a_healthy_launch_records_no_degradation() {
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", true);
        rec.degrade_unless("host_services", true);
        assert!(rec.finish().expect("enabled").degraded.is_empty());
    }

    #[test]
    fn an_unhealthy_subsystem_is_named() {
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", true);
        rec.degrade_unless("host_services", false);
        assert_eq!(
            rec.finish().expect("enabled").degraded,
            vec!["host_services".to_string()]
        );
    }

    #[test]
    fn a_disabled_recorder_records_no_degradation_either() {
        let mut rec = LaunchTraceRecorder::with_enabled("hvf", false);
        rec.degrade_unless("host_services", false);
        assert!(rec.finish().is_none());
    }

    #[test]
    fn recorded_acquisition_reflects_the_process_recorder() {
        // One test owns the process-wide recorder: the flags are set-once by
        // design, so a second test asserting "unset" would race this one.
        assert!(!recorded_acquisition().image_build);
        record_image_pull();
        record_image_build();
        assert_eq!(
            recorded_acquisition(),
            AcquisitionWork {
                image_pull: true,
                image_build: true
            }
        );
    }

    #[test]
    fn tracing_gate_trips_on_either_signal() {
        assert!(tracing_enabled_from(Some("1"), None));
        assert!(tracing_enabled_from(Some("true"), None));
        assert!(tracing_enabled_from(Some("TRUE"), None));
        assert!(tracing_enabled_from(None, Some("/tmp/sample.json")));
        assert!(!tracing_enabled_from(None, None));
        assert!(!tracing_enabled_from(Some("0"), None));
        assert!(!tracing_enabled_from(Some(""), Some("  ")));
    }
}
