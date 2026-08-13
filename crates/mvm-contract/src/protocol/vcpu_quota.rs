//! Measured vCPU quota record — what the HVF scheduler actually achieved.
//!
//! This type lives in the no_std + alloc contract so it can be serialized by
//! both the host supervisor and the wasm32 guest-side verifier without
//! duplicating the schema.

use serde::{Deserialize, Serialize};

/// What the HVF predictive scheduler measured for one vCPU run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VcpuQuotaRecord {
    pub target_millicores: u32,
    pub achieved_millicores: u32,
    pub period_ms: u32,
    pub measured_wall_ms: u64,
    pub measured_cpu_ms: u64,
    pub periods: u32,
}

impl VcpuQuotaRecord {
    /// Periods a run must complete before its measurement is long enough to
    /// attest to.
    pub const MIN_ATTESTABLE_PERIODS: u32 = 20;

    /// How far above target a run may land and still count as bounded.
    pub const TOLERANCE_PERCENT: u32 = 15;

    /// Whether this measurement witnesses a bound that actually held.
    #[must_use]
    pub fn bounded(&self) -> bool {
        if self.periods < Self::MIN_ATTESTABLE_PERIODS {
            return false;
        }
        // achieved <= target * (100 + TOLERANCE) / 100
        // Multiply both sides by 100 to stay in integer arithmetic.
        let lhs = u64::from(self.achieved_millicores).saturating_mul(100);
        let rhs = u64::from(self.target_millicores)
            .saturating_mul(u64::from(100 + Self::TOLERANCE_PERCENT));
        lhs <= rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(target: u32, achieved: u32, periods: u32) -> VcpuQuotaRecord {
        VcpuQuotaRecord {
            target_millicores: target,
            achieved_millicores: achieved,
            period_ms: 10,
            measured_wall_ms: u64::from(periods) * 10,
            measured_cpu_ms: u64::from(periods) * 10 * u64::from(achieved) / 1000,
            periods,
        }
    }

    #[test]
    fn a_quota_record_round_trips_through_json() {
        let r = record(500, 505, 20);
        let json = serde_json::to_string(&r).unwrap();
        let back: VcpuQuotaRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn an_unknown_field_in_a_quota_record_is_refused() {
        let json = r#"{
            "target_millicores": 500,
            "achieved_millicores": 505,
            "period_ms": 10,
            "measured_wall_ms": 200,
            "measured_cpu_ms": 100,
            "periods": 20,
            "extra": 1
        }"#;
        assert!(serde_json::from_str::<VcpuQuotaRecord>(json).is_err());
    }

    #[test]
    fn a_run_too_short_to_measure_is_not_bounded() {
        assert!(!record(500, 500, 19).bounded());
        assert!(record(500, 500, 20).bounded());
    }

    #[test]
    fn a_run_that_overshot_its_target_is_not_bounded() {
        // 700 vs 500 is a 40 % overshoot, well past the 15 % tolerance.
        assert!(!record(500, 700, 20).bounded());
    }

    #[test]
    fn a_run_inside_tolerance_is_bounded() {
        assert!(record(500, 505, 20).bounded());
    }

    #[test]
    fn a_run_under_its_target_is_a_bound() {
        assert!(record(500, 300, 20).bounded());
    }
}
