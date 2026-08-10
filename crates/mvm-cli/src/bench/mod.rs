//! MicroVM launch latency and density benchmarking harness — measures
//! runtime microVM launch latency and host footprint.
//!
//! This is a reusable library surface, not a shipped CLI verb: the
//! dev/CI interaction-latency gate drives it directly. Every launch
//! optimisation (kernel cmdline trim, handshake pipelining, the warm
//! pool) is judged against this harness — without measurement we'd
//! optimise the wrong thing. The measurement substrate here —
//! per-iteration host wall-clock timing, N-run statistics, a
//! versioned JSON report, and baseline regression-gating — is pure
//! and fully unit-tested via a mock [`LaunchProbe`](harness::LaunchProbe).
//!
//! The live probe MUST drive signed-plan admission so the harness measures
//! a launch shape that can actually ship. It is feature-gated behind
//! `libkrun-live` since it boots a real guest.

pub mod cold_launch;
pub mod cold_launch_runner;
pub mod harness;
pub mod interaction;
pub mod probe;
#[cfg(feature = "libkrun-live")]
pub mod probes;
pub mod regression;
pub mod report;
pub mod stats;

// `BootMarks` and the boot-timing-sidecar writer are the only bench-internal
// items another file (`probe.rs`, under `libkrun-live`) reaches through
// this module's path — everything else submodules need from each other they
// reach directly via `super::<submodule>`.
#[cfg(feature = "libkrun-live")]
pub(crate) use probes::write_boot_timing_sidecar;
#[cfg(feature = "libkrun-live")]
pub use stats::BootMarks;

use std::path::PathBuf;

use anyhow::Result;
use serde::Serialize;

use report::write_json_report;

fn default_report_path(kind: &str, stamp: &str) -> PathBuf {
    PathBuf::from(mvm_core::config::mvm_state_dir())
        .join("bench")
        .join(format!("{kind}-{stamp}.json"))
}

fn timestamp_for_report_path() -> String {
    // utc_now() is RFC3339 (`2026-05-29T12:34:56+00:00`); sanitise the
    // colons/plus/dot so it's a safe filename component.
    mvm_core::time::utc_now().replace([':', '+', '.'], "-")
}

pub fn write_report_with_latest<T: Serialize>(
    report: &T,
    out: Option<PathBuf>,
    kind: &str,
) -> Result<PathBuf> {
    let stamp = timestamp_for_report_path();
    let out_path = match out {
        Some(p) => p,
        None => default_report_path(kind, &stamp),
    };
    write_json_report(report, &out_path)?;
    if let Some(parent) = out_path.parent() {
        let latest = parent.join(format!("{kind}-latest.json"));
        let _ = write_json_report(report, &latest);
    }
    Ok(out_path)
}
