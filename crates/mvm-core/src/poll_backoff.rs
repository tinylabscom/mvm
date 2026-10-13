//! Shared backoff for "wait until a thing becomes true" polls.
//!
//! A polled condition is only observed on a probe, so the cadence is a floor
//! under every wait it measures. A flat tick coarser than the event being
//! waited for stops measuring the event and starts measuring the tick: a 50 ms
//! poll reported a guest that was ready in 18 ms as taking 54 ms, and reported
//! a supervisor that had already exited as taking a full tick to do it.
//!
//! Starting fine and backing off keeps a fast outcome cheap to notice while
//! bounding the number of probes a slow one costs.

use std::time::Duration;

/// First delay, in milliseconds. Small enough that an outcome arriving almost
/// immediately is not rounded up.
const BASE_MS: u64 = 1;

/// Ceiling, in milliseconds. Caps the error a slow outcome can be reported
/// with, and bounds the probe count.
const CAP_MS: u64 = 25;

/// Delay before probe `attempt` (0-based): 1 ms doubling to a 25 ms ceiling.
///
/// The shift saturates, so a caller that polls for a very long time cannot
/// overflow it.
#[must_use]
pub fn poll_delay(attempt: u32) -> Duration {
    let scaled = BASE_MS.saturating_mul(1u64 << attempt.min(16));
    Duration::from_millis(scaled.min(CAP_MS))
}

/// Ceiling for [`fine_poll_delay`], in milliseconds.
const FINE_CAP_MS: u64 = 2;

/// [`poll_delay`] capped at 2 ms, for a local event a launch is blocked on
/// and that a probe can see cheaply — a socket appearing, a process table
/// entry changing.
///
/// The doubling cadence is right when probes are expensive or the wait is
/// long. For an event that normally lands within tens of milliseconds it is a
/// tax: an outcome arriving at 13 ms is not seen until the 15 ms probe, and
/// one at 16 ms not until 31 ms. A boot waits on two such events back to back.
#[must_use]
pub fn fine_poll_delay(attempt: u32) -> Duration {
    poll_delay(attempt).min(Duration::from_millis(FINE_CAP_MS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_starts_fine_and_caps() {
        let ms = |a: u32| poll_delay(a).as_millis() as u64;
        assert_eq!(ms(0), 1, "a fast outcome must not be rounded up");
        assert_eq!(ms(1), 2);
        assert_eq!(ms(2), 4);
        assert_eq!(ms(3), 8);
        assert_eq!(ms(4), 16);
        assert_eq!(ms(5), CAP_MS, "capped");
        assert_eq!(
            ms(64),
            CAP_MS,
            "a large attempt count cannot overflow the shift"
        );
    }

    #[test]
    fn the_ceiling_bounds_how_wrong_a_slow_outcome_can_be() {
        // Whatever the outcome's real timing, it is observed within one cap.
        for attempt in 0..1000 {
            assert!(poll_delay(attempt).as_millis() as u64 <= CAP_MS);
        }
    }

    #[test]
    fn the_fine_cadence_starts_like_the_coarse_one_and_never_exceeds_2ms() {
        assert_eq!(fine_poll_delay(0), poll_delay(0));
        for attempt in 0..1000 {
            assert!(fine_poll_delay(attempt) <= Duration::from_millis(FINE_CAP_MS));
        }
        assert_eq!(fine_poll_delay(64), Duration::from_millis(FINE_CAP_MS));
    }

    #[test]
    fn a_slow_wait_costs_few_probes() {
        let mut elapsed = 0u64;
        let mut attempts = 0u32;
        while elapsed < 5_000 {
            elapsed += poll_delay(attempts).as_millis() as u64;
            attempts += 1;
        }
        assert!(attempts < 210, "5s of waiting took {attempts} probes");
    }
}
