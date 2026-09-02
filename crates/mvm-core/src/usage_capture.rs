//! Measured resource consumption for one workload run, and the sidecar
//! convention that carries it off the process that owned the VM.
//!
//! A metric is a choice between a host observation and nothing, rather than a
//! number plus flags, so an unobservable dimension cannot carry a number that
//! reads as zero. Every source this version defines is a host observation;
//! anything the untrusted guest says about itself would need a source of its
//! own, and none is defined until something produces one. The wire form is
//! flat (`source`/`value`/`mechanism`) and is validated on the way in, because
//! the file is written by one process and read by another.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub use mvm_contract::protocol::resource_controls::Mechanism;

/// Where a metric's number came from, or that there is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageSource {
    /// Observed by the host. The only source a verifier may treat as attested.
    Measured,
    /// This host could not observe this dimension on this backend.
    Unavailable,
}

/// One dimension's consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "MetricWire", try_from = "MetricWire")]
pub enum Metric {
    Measured { value: u64, mechanism: Mechanism },
    Unavailable,
}

impl Metric {
    #[must_use]
    pub const fn measured(value: u64, mechanism: Mechanism) -> Self {
        Self::Measured { value, mechanism }
    }

    #[must_use]
    pub const fn unavailable() -> Self {
        Self::Unavailable
    }

    /// The number, when there is one.
    #[must_use]
    pub const fn value(self) -> Option<u64> {
        match self {
            Self::Measured { value, .. } => Some(value),
            Self::Unavailable => None,
        }
    }

    #[must_use]
    pub const fn source(self) -> UsageSource {
        match self {
            Self::Measured { .. } => UsageSource::Measured,
            Self::Unavailable => UsageSource::Unavailable,
        }
    }
}

/// The flat wire form. Private: the validated enum is the only public shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricWire {
    source: UsageSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mechanism: Option<Mechanism>,
}

impl From<Metric> for MetricWire {
    fn from(metric: Metric) -> Self {
        match metric {
            Metric::Measured { value, mechanism } => Self {
                source: UsageSource::Measured,
                value: Some(value),
                mechanism: Some(mechanism),
            },
            Metric::Unavailable => Self {
                source: UsageSource::Unavailable,
                value: None,
                mechanism: None,
            },
        }
    }
}

impl TryFrom<MetricWire> for Metric {
    type Error = &'static str;

    fn try_from(wire: MetricWire) -> Result<Self, Self::Error> {
        match (wire.source, wire.value, wire.mechanism) {
            (UsageSource::Measured, Some(value), Some(mechanism)) => {
                Ok(Self::Measured { value, mechanism })
            }
            (UsageSource::Measured, _, _) => {
                Err("a measured metric must carry both a value and a mechanism")
            }
            (UsageSource::Unavailable, None, None) => Ok(Self::Unavailable),
            (UsageSource::Unavailable, _, _) => {
                Err("an unavailable metric must carry neither a value nor a mechanism")
            }
        }
    }
}

/// One run's consumption across every dimension this version records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageCapture {
    pub cpu_ms: Metric,
    pub peak_rss_mib: Metric,
    pub host_state_bytes: Metric,
    pub wall_ms: Metric,
}

impl Default for UsageCapture {
    /// Every dimension unobserved. A run that measured nothing still says so.
    fn default() -> Self {
        Self {
            cpu_ms: Metric::unavailable(),
            peak_rss_mib: Metric::unavailable(),
            host_state_bytes: Metric::unavailable(),
            wall_ms: Metric::unavailable(),
        }
    }
}

/// File name under `vm_state_dir` holding the captured usage.
pub const WORKLOAD_USAGE_FILE: &str = "workload.usage";

#[must_use]
pub fn usage_file_path(vm_state_dir: &Path) -> PathBuf {
    vm_state_dir.join(WORKLOAD_USAGE_FILE)
}

/// Read a previously-captured usage record.
///
/// An absent or unreadable file yields an all-unavailable record rather than
/// an error or a zero: "nothing was observed" is the honest answer, and it is
/// the same answer a backend that cannot observe anything writes deliberately.
#[must_use]
pub fn read_captured(vm_state_dir: &Path) -> UsageCapture {
    std::fs::read_to_string(usage_file_path(vm_state_dir))
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Persist a usage record beside the exit code.
pub fn write_captured(vm_state_dir: &Path, usage: &UsageCapture) -> std::io::Result<()> {
    let encoded = serde_json::to_string(usage).map_err(std::io::Error::other)?;
    std::fs::write(usage_file_path(vm_state_dir), encoded)
}

/// Byte total of a VM's state directory tree.
///
/// This is host-side overlay and copy-on-write growth, not the guest's view of
/// its own filesystem — which is why the recorded key is named for the host
/// state rather than for disk.
#[must_use]
pub fn host_state_bytes(vm_state_dir: &Path) -> Metric {
    Metric::measured(
        crate::disk_usage::tree_bytes(vm_state_dir),
        Mechanism::StateDirTreeBytes,
    )
}

/// A launch-to-teardown span in whole milliseconds, truncated rather than
/// rounded so a span shorter than a millisecond never reports time.
#[must_use]
pub fn wall_ms(span: std::time::Duration) -> Metric {
    Metric::measured(
        u64::try_from(span.as_millis()).unwrap_or(u64::MAX),
        Mechanism::HostLaunchSpan,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unavailable_metric_carries_no_number_to_misread() {
        let json = serde_json::to_string(&Metric::unavailable()).expect("serialize");
        assert_eq!(json, r#"{"source":"unavailable"}"#);
    }

    #[test]
    fn a_measured_metric_names_the_mechanism_that_produced_it() {
        let json = serde_json::to_string(&Metric::measured(4210, Mechanism::HvfSummedVcpuClock))
            .expect("serialize");
        assert_eq!(
            json,
            r#"{"source":"measured","value":4210,"mechanism":"hvf_summed_vcpu_clock"}"#
        );
    }

    #[test]
    fn an_unavailable_metric_carrying_a_value_is_refused_on_the_wire() {
        // Presence of a number under `unavailable` is the exact ambiguity the
        // encoding exists to prevent, so it must not survive a round trip.
        let err = serde_json::from_str::<Metric>(r#"{"source":"unavailable","value":5}"#);
        assert!(err.is_err(), "unavailable must not carry a value");
    }

    #[test]
    fn a_measured_metric_without_a_mechanism_is_refused_on_the_wire() {
        let err = serde_json::from_str::<Metric>(r#"{"source":"measured","value":5}"#);
        assert!(err.is_err(), "measured must name its mechanism");
    }

    #[test]
    fn a_source_this_version_does_not_define_is_refused_on_the_wire() {
        // Only a host observation may be stamped with a source at all in this
        // version. A record naming any other one — a guest self-report, a
        // vendor provider reading — must not parse into something a consumer
        // could mistake for an attested number.
        let err = serde_json::from_str::<Metric>(r#"{"source":"guest_reported","value":204800}"#);
        assert!(err.is_err(), "an undefined source must not parse");
    }

    #[test]
    fn every_metric_shape_round_trips_through_the_wire_form() {
        // The wire form is a flat struct that a validating `TryFrom` narrows,
        // so a round trip is the only thing proving the narrowing and the
        // widening agree on every shape rather than on the one the writer
        // happened to test.
        for metric in [
            Metric::unavailable(),
            Metric::measured(0, Mechanism::HostLaunchSpan),
            Metric::measured(4210, Mechanism::HostProcessCpu),
            Metric::measured(312, Mechanism::HostProcessRss),
            Metric::measured(91_234_304, Mechanism::StateDirTreeBytes),
            Metric::measured(u64::MAX, Mechanism::HvfSummedVcpuClock),
        ] {
            let json = serde_json::to_string(&metric).expect("serialize");
            assert_eq!(
                serde_json::from_str::<Metric>(&json).expect("deserialize"),
                metric,
                "{json}"
            );
        }
    }

    #[test]
    fn the_default_capture_says_nothing_was_observed_in_every_dimension() {
        // Not an empty object and not zeros: the record a run that measured
        // nothing produces still names each dimension and calls it
        // unobserved.
        let default = UsageCapture::default();
        for metric in [
            default.cpu_ms,
            default.peak_rss_mib,
            default.host_state_bytes,
            default.wall_ms,
        ] {
            assert_eq!(metric, Metric::unavailable());
            assert_eq!(metric.value(), None);
            assert_eq!(metric.source(), UsageSource::Unavailable);
        }
        assert_eq!(
            serde_json::to_string(&default).expect("serialize"),
            r#"{"cpu_ms":{"source":"unavailable"},"peak_rss_mib":{"source":"unavailable"},"host_state_bytes":{"source":"unavailable"},"wall_ms":{"source":"unavailable"}}"#
        );
    }

    #[test]
    fn a_capture_carrying_an_unknown_dimension_is_refused() {
        // `deny_unknown_fields` is what keeps a reader from accepting a record
        // written by a newer producer and then attesting the subset it
        // understood as the whole run.
        let err = serde_json::from_str::<UsageCapture>(
            r#"{"cpu_ms":{"source":"unavailable"},"peak_rss_mib":{"source":"unavailable"},"host_state_bytes":{"source":"unavailable"},"wall_ms":{"source":"unavailable"},"gpu_ms":{"source":"unavailable"}}"#,
        );
        assert!(err.is_err(), "an unknown dimension must not parse");
    }

    #[test]
    fn a_fully_measured_capture_round_trips() {
        let usage = UsageCapture {
            cpu_ms: Metric::measured(4210, Mechanism::HvfSummedVcpuClock),
            peak_rss_mib: Metric::measured(312, Mechanism::HostProcessRss),
            host_state_bytes: Metric::measured(91_234_304, Mechanism::StateDirTreeBytes),
            wall_ms: Metric::measured(61_004, Mechanism::HostLaunchSpan),
        };
        let json = serde_json::to_string(&usage).expect("serialize");
        assert_eq!(
            serde_json::from_str::<UsageCapture>(&json).expect("deserialize"),
            usage
        );
    }

    #[test]
    fn a_capture_round_trips_through_the_sidecar() {
        let dir = tempfile::tempdir().expect("tempdir");
        let usage = UsageCapture {
            cpu_ms: Metric::measured(4210, Mechanism::HostProcessCpu),
            ..UsageCapture::default()
        };
        write_captured(dir.path(), &usage).expect("write");
        assert_eq!(read_captured(dir.path()), usage);
    }

    #[test]
    fn an_absent_sidecar_reads_as_unavailable_never_as_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_captured(dir.path()), UsageCapture::default());
        assert_eq!(read_captured(dir.path()).cpu_ms, Metric::unavailable());
    }

    #[test]
    fn a_malformed_sidecar_reads_as_unavailable_never_as_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(usage_file_path(dir.path()), "{ not json").expect("write");
        assert_eq!(read_captured(dir.path()), UsageCapture::default());
    }

    #[test]
    fn an_absent_state_dir_measures_zero_bytes_rather_than_failing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = host_state_bytes(&dir.path().join("absent"));
        assert_eq!(bytes, Metric::measured(0, Mechanism::StateDirTreeBytes));
    }

    #[test]
    fn a_state_dir_with_content_measures_more_than_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("blob"), vec![0u8; 8192]).expect("write");
        assert!(host_state_bytes(dir.path()).value().expect("measured") >= 8192);
    }

    #[test]
    fn a_wall_span_is_recorded_in_whole_milliseconds() {
        assert_eq!(
            wall_ms(std::time::Duration::from_millis(61_004)),
            Metric::measured(61_004, Mechanism::HostLaunchSpan)
        );
    }

    #[test]
    fn a_sub_millisecond_span_is_zero_rather_than_rounded_up() {
        // Rounding up would let a run that never happened report time.
        assert_eq!(
            wall_ms(std::time::Duration::from_micros(400)),
            Metric::measured(0, Mechanism::HostLaunchSpan)
        );
    }
}
