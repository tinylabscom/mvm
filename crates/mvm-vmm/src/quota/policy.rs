//! Pure quota policy: `(millicores, period)` validation and per-period allowance/debt arithmetic.
//!
//! This module has no threads, no clocks, and no FFI. Every rule is unit-testable
//! on any host.

use std::time::Duration;

/// A validated CPU quota configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaConfig {
    millicores: u32,
    period: Duration,
}

/// CPU time the vCPU may consume in one period, and whether it must be held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeriodVerdict {
    /// True when the vCPU spent its allowance and must be held to the period boundary.
    pub hold: bool,
    /// Allowance available for the next period, after carried debt is repaid.
    pub allowance: Duration,
}

/// A quota policy with carried debt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaPolicy {
    config: QuotaConfig,
    debt: Duration,
}

impl QuotaConfig {
    /// Shortest enforceable period.
    pub const MIN_PERIOD: Duration = Duration::from_millis(5);
    /// Recommended default period.
    pub const DEFAULT_PERIOD: Duration = Duration::from_millis(10);
    /// Longest allowed period.
    pub const MAX_PERIOD: Duration = Duration::from_millis(100);
    /// Smallest run slice or hold that can be expressed without collapsing into
    /// the run loop's 1 ms hold quantum.
    pub const MIN_SLICE: Duration = Duration::from_millis(2);
    /// 1.0 core is the ceiling. This is a policy limit, not a consequence of
    /// the backend's vCPU count: HVF creates more than one now, and the
    /// scheduler charges their summed CPU time, so a multi-vCPU guest can
    /// consume more than one core's worth. Grants above this are refused
    /// rather than under-charged, so raising it is a deliberate widening of
    /// the bound and not a correctness fix.
    pub const MAX_MILLICORES: u32 = 1000;

    const DEFAULT_PERIOD_MS: u32 = 10;
    const MIN_PERIOD_MS: u32 = 5;
    const MAX_PERIOD_MS: u32 = 100;
    const MIN_SLICE_US: u64 = 2_000;

    /// Pick the shortest period at or above the default that can express `millicores`.
    pub fn for_share(millicores: u32) -> anyhow::Result<Self> {
        if millicores == 0 || millicores > Self::MAX_MILLICORES {
            anyhow::bail!(
                "CPU share must be between 1 and {max} millicores (1.0 core) on this tier; got {got}",
                max = Self::MAX_MILLICORES,
                got = millicores
            );
        }

        let period_for_slice = 2_000_u32.div_ceil(millicores);
        let period_for_hold = 2_000_u32.div_ceil(Self::MAX_MILLICORES - millicores);
        let period_ms = Self::DEFAULT_PERIOD_MS
            .max(period_for_slice)
            .max(period_for_hold);

        if period_ms > Self::MAX_PERIOD_MS {
            anyhow::bail!(
                "CPU share {millicores} millicores is outside the expressible range [20, 980] millicores; no period between {min} ms and {max} ms keeps both the run slice and the hold above {min_slice} ms",
                min = Self::MIN_PERIOD_MS,
                max = Self::MAX_PERIOD_MS,
                min_slice = Self::MIN_SLICE.as_millis()
            );
        }

        Self::new(millicores, Duration::from_millis(u64::from(period_ms)))
    }

    /// Validate an explicit period.
    pub fn new(millicores: u32, period: Duration) -> anyhow::Result<Self> {
        if millicores == 0 || millicores > Self::MAX_MILLICORES {
            anyhow::bail!(
                "CPU share must be between 1 and {max} millicores (1.0 core) on this tier; got {got}",
                max = Self::MAX_MILLICORES,
                got = millicores
            );
        }
        if period < Self::MIN_PERIOD {
            anyhow::bail!(
                "quota period {period:?} is below the {min:?} floor",
                min = Self::MIN_PERIOD
            );
        }
        if period > Self::MAX_PERIOD {
            anyhow::bail!(
                "quota period {period:?} is above the {max:?} ceiling",
                max = Self::MAX_PERIOD
            );
        }

        let period_us = period.as_micros();
        let slice_us = period_us * u128::from(millicores) / 1_000;
        let hold_us = period_us - slice_us;

        if slice_us < u128::from(Self::MIN_SLICE_US) {
            anyhow::bail!(
                "quota period {period:?} with share {millicores} millicores yields a run slice of {slice_us} µs, below the {min_slice:?} minimum",
                min_slice = Self::MIN_SLICE
            );
        }
        if hold_us < u128::from(Self::MIN_SLICE_US) {
            anyhow::bail!(
                "quota period {period:?} with share {millicores} millicores yields a hold of {hold_us} µs, below the {min_slice:?} minimum",
                min_slice = Self::MIN_SLICE
            );
        }

        Ok(Self { millicores, period })
    }

    pub fn millicores(&self) -> u32 {
        self.millicores
    }

    pub fn period(&self) -> Duration {
        self.period
    }

    /// CPU time the vCPU may burn per period.
    pub fn slice(&self) -> Duration {
        let us = self.period.as_micros() * u128::from(self.millicores) / 1_000;
        Duration::from_micros(u64::try_from(us).expect("slice fits in u64"))
    }

    /// Guest-visible worst-case freeze: `period × (1 - quota)`.
    pub fn worst_case_stall(&self) -> Duration {
        self.period.saturating_sub(self.slice())
    }
}

impl QuotaPolicy {
    pub fn new(config: QuotaConfig) -> Self {
        Self {
            config,
            debt: Duration::ZERO,
        }
    }

    pub fn config(&self) -> &QuotaConfig {
        &self.config
    }

    pub fn debt(&self) -> Duration {
        self.debt
    }

    /// CPU the vCPU may burn this period: this period's slice less the debt carried in.
    pub fn allowance(&self) -> Duration {
        self.config.slice().saturating_sub(self.debt)
    }

    /// Fold one period's measurement in and update the carried debt.
    pub fn settle(&mut self, consumed_total: Duration, periods_elapsed: u32) -> PeriodVerdict {
        let slice = self.config.slice();
        let entitlement = slice * periods_elapsed;
        let overshoot = consumed_total.saturating_sub(entitlement);
        self.debt = overshoot.min(self.config.period());
        let hold = consumed_total >= entitlement;
        PeriodVerdict {
            hold,
            allowance: self.allowance(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_share_lands_on_the_recommended_ten_millisecond_period() {
        let cfg = QuotaConfig::for_share(500).unwrap();
        assert_eq!(cfg.period(), Duration::from_millis(10));
    }

    #[test]
    fn a_lopsided_share_lengthens_the_period_rather_than_missing_its_target() {
        assert_eq!(
            QuotaConfig::for_share(100).unwrap().period(),
            Duration::from_millis(20)
        );
        assert_eq!(
            QuotaConfig::for_share(900).unwrap().period(),
            Duration::from_millis(20)
        );
    }

    #[test]
    fn a_share_no_period_can_express_is_refused_with_the_expressible_range() {
        let err = QuotaConfig::for_share(19).unwrap_err().to_string();
        assert!(err.contains("20"), "{err}");
        assert!(err.contains("980"), "{err}");
        let err = QuotaConfig::for_share(981).unwrap_err().to_string();
        assert!(err.contains("20"), "{err}");
        assert!(err.contains("980"), "{err}");
    }

    #[test]
    fn a_share_over_the_single_vcpu_ceiling_is_refused() {
        let err = QuotaConfig::for_share(1500).unwrap_err().to_string();
        assert!(err.contains("1000"), "{err}");
    }

    #[test]
    fn a_period_below_the_floor_is_refused() {
        assert!(QuotaConfig::new(500, Duration::from_millis(4)).is_err());
        assert!(QuotaConfig::new(500, Duration::from_millis(5)).is_ok());
    }

    #[test]
    fn a_period_over_the_ceiling_is_refused() {
        assert!(QuotaConfig::new(500, Duration::from_millis(101)).is_err());
        assert!(QuotaConfig::new(500, Duration::from_millis(100)).is_ok());
    }

    #[test]
    fn an_explicit_period_that_collapses_a_slice_is_refused() {
        // 100 millicores at 10 ms → 1 ms run slice, below MIN_SLICE.
        assert!(QuotaConfig::new(100, Duration::from_millis(10)).is_err());
        // 900 millicores at 10 ms → 1 ms hold, below MIN_SLICE.
        assert!(QuotaConfig::new(900, Duration::from_millis(10)).is_err());
    }

    #[test]
    fn the_slice_is_the_period_scaled_by_the_share() {
        assert_eq!(
            QuotaConfig::new(500, Duration::from_millis(10))
                .unwrap()
                .slice(),
            Duration::from_millis(5)
        );
        assert_eq!(
            QuotaConfig::new(250, Duration::from_millis(20))
                .unwrap()
                .slice(),
            Duration::from_millis(5)
        );
    }

    #[test]
    fn the_worst_case_stall_is_the_period_less_the_slice() {
        assert_eq!(
            QuotaConfig::new(500, Duration::from_millis(10))
                .unwrap()
                .worst_case_stall(),
            Duration::from_millis(5)
        );
    }

    #[test]
    fn an_unspent_period_carries_no_credit_forward() {
        let cfg = QuotaConfig::new(500, Duration::from_millis(10)).unwrap();
        let mut policy = QuotaPolicy::new(cfg);
        // Spent 1 ms of a 5 ms slice.
        policy.settle(Duration::from_millis(1), 1);
        assert_eq!(policy.allowance(), cfg.slice());
        assert_eq!(policy.debt(), Duration::ZERO);
    }

    #[test]
    fn an_overspent_period_carries_its_overshoot_as_debt() {
        let cfg = QuotaConfig::new(500, Duration::from_millis(10)).unwrap();
        let mut policy = QuotaPolicy::new(cfg);
        let slice = cfg.slice();
        policy.settle(slice + Duration::from_millis(2), 1);
        assert_eq!(policy.debt(), Duration::from_millis(2));
        assert_eq!(policy.allowance(), slice - Duration::from_millis(2));
    }

    #[test]
    fn debt_repays_across_periods_until_the_average_converges() {
        let cfg = QuotaConfig::new(500, Duration::from_millis(10)).unwrap();
        let mut policy = QuotaPolicy::new(cfg);
        let slice = cfg.slice();

        // Overshoot by 2 ms in period 1.
        policy.settle(slice + Duration::from_millis(2), 1);
        assert_eq!(policy.debt(), Duration::from_millis(2));

        // Exactly on budget in period 2: debt should shrink.
        policy.settle(slice + slice, 2);
        assert_eq!(policy.debt(), Duration::ZERO);

        // Stay there.
        policy.settle(slice * 3, 3);
        assert_eq!(policy.debt(), Duration::ZERO);
    }

    #[test]
    fn debt_never_exceeds_one_period_so_a_stall_cannot_compound() {
        let cfg = QuotaConfig::new(500, Duration::from_millis(10)).unwrap();
        let mut policy = QuotaPolicy::new(cfg);
        let slice = cfg.slice();
        let period = cfg.period();

        // Spend slice + 10× period in one period.
        policy.settle(slice + period * 10, 1);
        assert_eq!(policy.debt(), period);
        assert_eq!(policy.allowance(), Duration::ZERO);
    }

    #[test]
    fn a_period_that_did_not_exhaust_its_allowance_needs_no_hold() {
        let cfg = QuotaConfig::new(500, Duration::from_millis(10)).unwrap();
        let mut policy = QuotaPolicy::new(cfg);
        let verdict = policy.settle(Duration::from_millis(1), 1);
        assert!(!verdict.hold);
    }

    #[test]
    fn a_period_that_spent_its_allowance_must_hold() {
        let cfg = QuotaConfig::new(500, Duration::from_millis(10)).unwrap();
        let mut policy = QuotaPolicy::new(cfg);
        let verdict = policy.settle(cfg.slice(), 1);
        assert!(verdict.hold);
    }
}
