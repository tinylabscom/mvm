//! VM-scoped FlowMux budgets and rate limits.

use std::sync::{Arc, Mutex};

use mvm_core::rate_limit::TokenBucket;

use super::registry::{self, RegistryLimits, VmFlowBudget};

/// Host ceiling for concurrent guest processes authenticated to one VM's
/// endpoint. Counting before the handshake also prevents idle handshake
/// sockets from creating an unbounded thread set.
pub const MAX_CONCURRENT_FLOWMUX_SESSIONS: usize = 16;

/// Per-session rate limiter for new connection/association/resolve attempts.
///
/// A guest can otherwise force the host to open an unbounded number of TCP
/// connections, UDP associations, or DNS queries per second. Each class gets
/// its own one-second-burst token bucket; zero capacity disables limiting.
#[derive(Debug)]
pub struct ConnectionRateLimiter {
    tcp: Mutex<TokenBucket>,
    udp: Mutex<TokenBucket>,
    dns: Mutex<TokenBucket>,
    icmp: Mutex<TokenBucket>,
}

/// Endpoint-scoped resources shared by every FlowMux session for one VM.
pub struct FlowMuxVmResources {
    pub(super) registry_budget: Arc<VmFlowBudget>,
    pub(super) rate_limiter: Arc<ConnectionRateLimiter>,
    pub(super) icmp_rate: Arc<crate::supervisor::egress_rate::EgressRateGuard>,
    session_slots: Arc<tokio::sync::Semaphore>,
}

impl FlowMuxVmResources {
    /// Build the shared owner from the admitted signed limits and host runtime
    /// bounds that are not yet plan-configurable.
    #[must_use]
    pub fn new(network: mvm_core::plan::NetworkLimits) -> Self {
        let limits = RegistryLimits::from_network_limits(network);
        Self {
            registry_budget: Arc::new(VmFlowBudget::new(network, limits.max_icmp)),
            rate_limiter: Arc::new(ConnectionRateLimiter::from_limits(&limits)),
            icmp_rate: Arc::new(crate::supervisor::egress_rate::EgressRateGuard::builder().build()),
            session_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FLOWMUX_SESSIONS)),
        }
    }

    pub(super) fn from_registry_limits(limits: RegistryLimits) -> Self {
        Self {
            registry_budget: Arc::new(VmFlowBudget::from_registry_limits(limits)),
            rate_limiter: Arc::new(ConnectionRateLimiter::from_limits(&limits)),
            icmp_rate: Arc::new(crate::supervisor::egress_rate::EgressRateGuard::builder().build()),
            session_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FLOWMUX_SESSIONS)),
        }
    }

    /// Reserve one endpoint session without waiting. The owned permit is held
    /// by the serving task and returns capacity on every exit path.
    pub fn try_acquire_session(self: &Arc<Self>) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.session_slots).try_acquire_owned().ok()
    }
}

impl ConnectionRateLimiter {
    /// Build a limiter from the per-class rates in [`RegistryLimits`].
    pub fn from_limits(limits: &RegistryLimits) -> Self {
        Self {
            tcp: Mutex::new(TokenBucket::new(limits.tcp_connect_rate)),
            udp: Mutex::new(TokenBucket::new(limits.udp_open_rate)),
            dns: Mutex::new(TokenBucket::new(limits.dns_resolve_rate)),
            icmp: Mutex::new(TokenBucket::new(limits.icmp_echo_rate)),
        }
    }

    /// Try to admit one new flow of `class`. Returns `true` when admitted or
    /// when the limiter for this class is disabled.
    pub fn try_open(&self, class: registry::FlowClass) -> bool {
        let bucket = match class {
            // A typed HTTP flow ends in a host-originated TCP connection, so
            // it spends the same budget rather than getting a private one to
            // route around it.
            registry::FlowClass::Tcp | registry::FlowClass::Http => &self.tcp,
            registry::FlowClass::Udp => &self.udp,
            registry::FlowClass::Dns => &self.dns,
            registry::FlowClass::Icmp => &self.icmp,
        };
        let mut guard = bucket.lock().expect("rate limiter bucket poisoned");
        // A zero-capacity bucket means "unlimited" for this class.
        if guard.capacity() == 0.0 {
            return true;
        }
        guard.try_take()
    }
}
