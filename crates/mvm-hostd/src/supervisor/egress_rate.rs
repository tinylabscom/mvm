//! Per-workload admission guard shared by the metered egress verbs.
//!
//! DNS and ICMP are both request/response verbs the host performs on a guest's
//! behalf, and both need the same two limits for the same reason: a guest that
//! is compromised, or merely looping, must not turn the host into an
//! amplifier. A token bucket caps the sustained rate and a semaphore caps
//! simultaneity; either one full refuses without waiting, so backpressure is a
//! refusal the caller can see rather than an unbounded queue.
//!
//! Neither limit is protocol-specific, which is why this is one type rather
//! than a copy per verb — a copy would drift, and the drift would be silent.

use std::sync::Mutex;

use mvm_core::rate_limit::TokenBucket;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Default sustained request rate for one workload endpoint.
pub const DEFAULT_REQUESTS_PER_SEC: u32 = 100;
/// Default number of simultaneous in-flight requests for one workload endpoint.
pub const DEFAULT_MAX_INFLIGHT: usize = 32;

/// Shared per-workload admission guard.
pub struct EgressRateGuard {
    bucket: Mutex<TokenBucket>,
    inflight: Semaphore,
}

impl EgressRateGuard {
    /// Build a guard with an explicit sustained rate and concurrency cap.
    pub fn new(requests_per_sec: u32, max_inflight: usize) -> Self {
        Self {
            bucket: Mutex::new(TokenBucket::new(requests_per_sec)),
            inflight: Semaphore::new(max_inflight),
        }
    }

    /// Admit one request, or return `None` without waiting when either limit is
    /// full.
    pub async fn admit(&self) -> Option<SemaphorePermit<'_>> {
        self.try_admit()
    }

    /// The same decision without an async context, for the blocking accept
    /// paths. Neither limit ever waits, so this is the whole of `admit`.
    pub fn try_admit(&self) -> Option<SemaphorePermit<'_>> {
        let permit = self.inflight.try_acquire().ok()?;
        let Ok(mut bucket) = self.bucket.lock() else {
            return None;
        };
        bucket.try_take().then_some(permit)
    }
}

impl Default for EgressRateGuard {
    fn default() -> Self {
        Self::new(DEFAULT_REQUESTS_PER_SEC, DEFAULT_MAX_INFLIGHT)
    }
}
