//! Resident-memory accounting for warm pools.
//!
//! Warm-pool density is governed by *measured* resident memory, not the
//! configured per-VM cap: copy-on-write restores resident far below cap, so the
//! first sibling to finish restoring measures the real footprint and subsequent
//! siblings are charged that learned estimate plus a safety margin. Two
//! independent limiters gate admission — a [`ResidentMemoryAccountant`] (bytes)
//! and a [`SpawnConcurrencyGate`] (in-flight boots) — because "how much memory
//! fits" and "how many can boot at once" are different questions.

/// One sibling's memory charge: the configured cap, a conservative pre-measure
/// charge, and the observations that refine it once the VM is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MemoryCharge {
    pub configured_limit_mib: u64,
    pub conservative_charge_mib: u64,
    pub observed_restore_rss_mib: Option<u64>,
    pub observed_idle_rss_mib: Option<u64>,
    pub observed_peak_rss_mib: Option<u64>,
    pub dirty_private_mib: Option<u64>,
}

/// The host memory split: total minus what's reserved for the host is the
/// budget guests may be charged against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMemoryBudget {
    pub total_mib: u64,
    pub reserved_for_host_mib: u64,
}

impl HostMemoryBudget {
    /// Memory available to charge guests against.
    pub fn guest_budget_mib(self) -> u64 {
        self.total_mib.saturating_sub(self.reserved_for_host_mib)
    }
}

/// Learned per-pool memory model. Charges the conservative estimate until the
/// first restore is measured, then the high-water learned resident estimate
/// plus a safety margin — so a pool of copy-on-write siblings packs to real
/// footprint, not to the configured cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolMemoryModel {
    pub configured_mib: u64,
    pub initial_charge_mib: u64,
    pub learned_restore_mib: Option<u64>,
    pub safety_factor_percent: u64,
}

impl PoolMemoryModel {
    pub fn new(configured_mib: u64, initial_charge_mib: u64, safety_factor_percent: u64) -> Self {
        Self {
            configured_mib,
            initial_charge_mib,
            learned_restore_mib: None,
            safety_factor_percent,
        }
    }

    /// Fold in a measured restore RSS, keeping the high-water mark.
    pub fn observe_restore_rss(&mut self, rss_mib: u64) {
        self.learned_restore_mib = Some(
            self.learned_restore_mib
                .map_or(rss_mib, |prev| prev.max(rss_mib)),
        );
    }

    /// What to charge the next sibling: learned + safety once measured, else the
    /// conservative initial charge.
    pub fn next_charge_mib(self) -> u64 {
        match self.learned_restore_mib {
            Some(rss) => rss.saturating_add(rss.saturating_mul(self.safety_factor_percent) / 100),
            None => self.initial_charge_mib,
        }
    }
}

/// A memory charge was refused: not enough budget remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionDenied {
    pub requested_mib: u64,
    pub available_mib: u64,
}

impl core::fmt::Display for AdmissionDenied {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "memory admission denied: requested {} MiB, {} MiB available",
            self.requested_mib, self.available_mib
        )
    }
}

impl std::error::Error for AdmissionDenied {}

/// Tracks total resident charge against the guest budget. Distinct from the
/// spawn-concurrency gate: this limits *bytes*, not *count*.
#[derive(Debug, Clone)]
pub struct ResidentMemoryAccountant {
    budget_mib: u64,
    charged_mib: u64,
}

impl ResidentMemoryAccountant {
    pub fn new(budget_mib: u64) -> Self {
        Self {
            budget_mib,
            charged_mib: 0,
        }
    }

    pub fn charged_mib(&self) -> u64 {
        self.charged_mib
    }

    pub fn available_mib(&self) -> u64 {
        self.budget_mib.saturating_sub(self.charged_mib)
    }

    /// Reserve `charge_mib` if it fits, else fail closed with the shortfall.
    pub fn try_admit(&mut self, charge_mib: u64) -> Result<(), AdmissionDenied> {
        if charge_mib > self.available_mib() {
            return Err(AdmissionDenied {
                requested_mib: charge_mib,
                available_mib: self.available_mib(),
            });
        }
        self.charged_mib += charge_mib;
        Ok(())
    }

    /// Release a previously admitted charge.
    pub fn release(&mut self, charge_mib: u64) {
        self.charged_mib = self.charged_mib.saturating_sub(charge_mib);
    }
}

/// Limits how many VMs may boot/restore concurrently — independent of the
/// memory accountant, so a burst of small-footprint restores is still bounded
/// by in-flight count even when memory is plentiful.
#[derive(Debug, Clone)]
pub struct SpawnConcurrencyGate {
    max_in_flight: usize,
    in_flight: usize,
}

impl SpawnConcurrencyGate {
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            max_in_flight,
            in_flight: 0,
        }
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    /// Acquire a boot slot if one is free.
    pub fn try_acquire(&mut self) -> bool {
        if self.in_flight >= self.max_in_flight {
            return false;
        }
        self.in_flight += 1;
        true
    }

    pub fn release(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_charges_conservatively_until_a_restore_is_measured() {
        let mut pool = PoolMemoryModel::new(2048, 512, 20);
        assert_eq!(
            pool.next_charge_mib(),
            512,
            "no measurement yet → conservative"
        );
        pool.observe_restore_rss(140);
        assert_eq!(pool.next_charge_mib(), 168, "learned 140 + 20% safety");
    }

    #[test]
    fn observe_restore_rss_keeps_the_high_water_mark() {
        let mut pool = PoolMemoryModel::new(2048, 512, 0);
        pool.observe_restore_rss(140);
        pool.observe_restore_rss(120); // lower — ignored
        assert_eq!(pool.next_charge_mib(), 140);
        pool.observe_restore_rss(200); // higher — adopted
        assert_eq!(pool.next_charge_mib(), 200);
    }

    #[test]
    fn accountant_admits_until_budget_then_fails_closed() {
        let mut acct = ResidentMemoryAccountant::new(300);
        assert!(acct.try_admit(140).is_ok());
        assert!(acct.try_admit(140).is_ok());
        assert_eq!(acct.charged_mib(), 280);
        let denied = acct.try_admit(140).unwrap_err();
        assert_eq!(denied.available_mib, 20);
        acct.release(140);
        assert!(acct.try_admit(140).is_ok(), "release frees budget");
    }

    #[test]
    fn spawn_gate_is_independent_of_memory() {
        let mut gate = SpawnConcurrencyGate::new(2);
        assert!(gate.try_acquire());
        assert!(gate.try_acquire());
        assert!(!gate.try_acquire(), "at capacity");
        assert_eq!(gate.in_flight(), 2);
        gate.release();
        assert!(gate.try_acquire(), "release frees a slot");
    }

    #[test]
    fn host_budget_subtracts_host_reservation() {
        let budget = HostMemoryBudget {
            total_mib: 32768,
            reserved_for_host_mib: 4096,
        };
        assert_eq!(budget.guest_budget_mib(), 28672);
    }
}
