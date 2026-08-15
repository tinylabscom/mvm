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
//!
//! Raw TCP tunnels draw on the same token bucket but a **separate** simultaneity
//! pool. A request/response verb holds its slot for one round trip; a tunnel
//! holds one for as long as the guest keeps the connection open. Sharing one
//! pool would let a handful of long-lived tunnels take every slot and leave the
//! guest unable to resolve a name — a self-inflicted denial of service in the
//! guard that exists to prevent one. The rate limit is genuinely shared: a
//! connect storm is host work whichever verb asks for it.

use std::sync::Mutex;

use mvm_core::rate_limit::TokenBucket;
use tokio::sync::{Semaphore, SemaphorePermit};

/// Default sustained request rate for one workload endpoint.
pub const DEFAULT_REQUESTS_PER_SEC: u32 = 100;
/// Default number of simultaneous in-flight requests for one workload endpoint.
pub const DEFAULT_MAX_INFLIGHT: usize = 32;
/// Default number of simultaneous raw tunnels for one workload endpoint.
pub const DEFAULT_MAX_TUNNELS: usize = 32;

/// Shared per-workload admission guard.
pub struct EgressRateGuard {
    bucket: Mutex<TokenBucket>,
    inflight: Semaphore,
    tunnels: Semaphore,
}

impl EgressRateGuard {
    /// Start building a guard. Every knob defaults to the module constants.
    pub fn builder() -> EgressRateGuardBuilder {
        EgressRateGuardBuilder::default()
    }

    /// Admit one request/response call, or return `None` without waiting when
    /// either limit is full.
    pub async fn admit(&self) -> Option<SemaphorePermit<'_>> {
        self.try_admit()
    }

    /// The same decision without an async context, for the blocking accept
    /// paths. Neither limit ever waits, so this is the whole of `admit`.
    pub fn try_admit(&self) -> Option<SemaphorePermit<'_>> {
        self.take(&self.inflight)
    }

    /// Admit one raw tunnel. The returned permit is held for the whole splice,
    /// so this draws on the tunnel pool rather than the request pool.
    pub fn try_admit_tunnel(&self) -> Option<SemaphorePermit<'_>> {
        self.take(&self.tunnels)
    }

    /// Take one slot from `pool` and one token from the shared bucket. A slot
    /// taken without a token is released again, so a full bucket never leaks
    /// simultaneity.
    fn take<'a>(&'a self, pool: &'a Semaphore) -> Option<SemaphorePermit<'a>> {
        let permit = pool.try_acquire().ok()?;
        let Ok(mut bucket) = self.bucket.lock() else {
            return None;
        };
        bucket.try_take().then_some(permit)
    }
}

impl Default for EgressRateGuard {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// Builder for [`EgressRateGuard`].
pub struct EgressRateGuardBuilder {
    requests_per_sec: u32,
    max_inflight: usize,
    max_tunnels: usize,
}

impl Default for EgressRateGuardBuilder {
    fn default() -> Self {
        Self {
            requests_per_sec: DEFAULT_REQUESTS_PER_SEC,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            max_tunnels: DEFAULT_MAX_TUNNELS,
        }
    }
}

impl EgressRateGuardBuilder {
    /// Sustained request rate across every metered verb.
    pub fn requests_per_sec(mut self, requests_per_sec: u32) -> Self {
        self.requests_per_sec = requests_per_sec;
        self
    }

    /// Simultaneous request/response calls.
    pub fn max_inflight(mut self, max_inflight: usize) -> Self {
        self.max_inflight = max_inflight;
        self
    }

    /// Simultaneous raw tunnels.
    pub fn max_tunnels(mut self, max_tunnels: usize) -> Self {
        self.max_tunnels = max_tunnels;
        self
    }

    /// Finish the guard.
    pub fn build(self) -> EgressRateGuard {
        EgressRateGuard {
            bucket: Mutex::new(TokenBucket::new(self.requests_per_sec)),
            inflight: Semaphore::new(self.max_inflight),
            tunnels: Semaphore::new(self.max_tunnels),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnels_and_requests_draw_on_separate_pools() {
        let guard = EgressRateGuard::builder()
            .max_inflight(1)
            .max_tunnels(1)
            .build();
        let _tunnel = guard.try_admit_tunnel().expect("first tunnel is admitted");
        assert!(
            guard.try_admit_tunnel().is_none(),
            "the tunnel pool is capped independently"
        );
        assert!(
            guard.try_admit().is_some(),
            "a held tunnel must not starve the request/response verbs"
        );
    }

    #[test]
    fn a_released_tunnel_returns_its_slot() {
        let guard = EgressRateGuard::builder().max_tunnels(1).build();
        let tunnel = guard.try_admit_tunnel().expect("first tunnel is admitted");
        assert!(guard.try_admit_tunnel().is_none());
        drop(tunnel);
        assert!(
            guard.try_admit_tunnel().is_some(),
            "closing a tunnel frees its slot"
        );
    }

    #[test]
    fn tunnels_and_requests_share_the_rate_limit() {
        let guard = EgressRateGuard::builder().requests_per_sec(1).build();
        assert!(guard.try_admit_tunnel().is_some(), "the one token is spent");
        assert!(
            guard.try_admit().is_none(),
            "a tunnel connect draws on the same sustained rate as a query"
        );
    }

    #[test]
    fn a_bucket_refusal_returns_the_tunnel_slot() {
        let guard = EgressRateGuard::builder()
            .requests_per_sec(0)
            .max_tunnels(1)
            .build();
        assert!(guard.try_admit_tunnel().is_none(), "no tokens, no tunnel");
        assert_eq!(
            guard.tunnels.available_permits(),
            1,
            "a refusal on the bucket must hand back the slot it took"
        );
    }
}
