//! Serializable teardown observations, without a runtime driver handle.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct StopTiming {
    pub attach: Duration,
    pub endpoint_reaping: Duration,
    pub driver_kill: Duration,
    pub console_cleanup: Duration,
    pub total: Duration,
    pub driver_detail: Option<StopDetail>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct StopDetail {
    pub supervisor_signal: Duration,
    pub pid_disappearance: Duration,
    pub force_kill_wait: Duration,
    pub state_cleanup: Duration,
}

impl From<mvm_runtime::workload_runner::StopTiming> for StopTiming {
    fn from(value: mvm_runtime::workload_runner::StopTiming) -> Self {
        Self {
            attach: value.attach,
            endpoint_reaping: value.endpoint_reaping,
            driver_kill: value.driver_kill,
            console_cleanup: value.console_cleanup,
            total: value.total,
            driver_detail: value.driver_detail.map(|detail| StopDetail {
                supervisor_signal: detail.supervisor_signal,
                pid_disappearance: detail.pid_disappearance,
                force_kill_wait: detail.force_kill_wait,
                state_cleanup: detail.state_cleanup,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_observations_preserve_every_duration_and_roundtrip() {
        let runtime = mvm_runtime::workload_runner::StopTiming {
            attach: Duration::from_nanos(1),
            endpoint_reaping: Duration::from_nanos(2),
            driver_kill: Duration::from_nanos(3),
            console_cleanup: Duration::from_nanos(4),
            total: Duration::from_nanos(5),
            driver_detail: Some(mvm_vmm::driver::RunningVmStopTiming {
                supervisor_signal: Duration::from_nanos(6),
                pid_disappearance: Duration::from_nanos(7),
                force_kill_wait: Duration::from_nanos(8),
                state_cleanup: Duration::from_nanos(9),
            }),
        };
        let report = StopTiming::from(runtime);
        assert_eq!(
            [
                report.attach,
                report.endpoint_reaping,
                report.driver_kill,
                report.console_cleanup,
                report.total
            ],
            [1, 2, 3, 4, 5].map(Duration::from_nanos)
        );
        let detail = report.driver_detail.unwrap();
        assert_eq!(
            [
                detail.supervisor_signal,
                detail.pid_disappearance,
                detail.force_kill_wait,
                detail.state_cleanup
            ],
            [6, 7, 8, 9].map(Duration::from_nanos)
        );
        assert_eq!(
            serde_json::from_str::<StopTiming>(&serde_json::to_string(&report).unwrap()).unwrap(),
            report
        );
    }
}
