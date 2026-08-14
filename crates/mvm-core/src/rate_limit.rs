//! Shared token-bucket rate limiting primitives.

use std::time::Instant;

/// Lazily refilled token bucket with a one-second burst capacity.
// allow(secret-debug): numeric rate-limit state only; not a secret.
#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a full bucket whose rate and burst capacity are `tokens_per_sec`.
    pub fn new(tokens_per_sec: u32) -> Self {
        let capacity = f64::from(tokens_per_sec);
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec: capacity,
            last_refill: Instant::now(),
        }
    }

    /// The configured burst capacity (also the per-second rate).
    pub fn capacity(&self) -> f64 {
        self.capacity
    }

    /// Consume one token when available.
    pub fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        let refill = elapsed.as_secs_f64() * self.refill_per_sec;
        if refill > 0.0 {
            self.tokens = (self.tokens + refill).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_rate_never_admits() {
        let mut bucket = TokenBucket::new(0);
        assert!(!bucket.try_take());
        assert!(!bucket.try_take());
    }

    #[test]
    fn one_per_second_admits_once_then_denies_immediately() {
        let mut bucket = TokenBucket::new(1);
        assert!(bucket.try_take());
        assert!(!bucket.try_take());
    }

    #[test]
    fn starts_at_one_second_of_burst_capacity() {
        let mut bucket = TokenBucket::new(5);
        for _ in 0..5 {
            assert!(bucket.try_take());
        }
        assert!(!bucket.try_take());
    }
}
