//! `EgressEnforcer` — the low seam the host-side egress enforcement (the
//! mvm-hostd supervisor's nftables default-deny, and later L4/L7) sits behind.
//!
//! This crate stays low (it depends only on `mvm-core` / `mvm-sdk`), so the
//! actual enforcement — `nft` shell-out, the L4 gate, the L7 proxy — can't
//! move down here; those need `tokio` and `mvm-hostd` internals. So the seam
//! is just the *contract*: it names what an enforcer does over the same
//! `mvm_core::network_policy::NetworkPolicy` the [`NetworkSpec`] already
//! carries (whose `Default` is `deny_all()` — claim 10). The concrete impl
//! (`SupervisorEgressEnforcer`) lives in mvm-hostd and adapts the existing
//! `FirewallEnforcer`.
//!
//! [`NetworkSpec`]: crate::NetworkSpec

use mvm_core::network_policy::NetworkPolicy;

/// Per-VM wiring an egress enforcer needs to scope its rules — the same three
/// fields as mvm-hostd's `FirewallSpec`, lifted into this low crate so the
/// supervisor can convert without a downward dependency. `tap_iface` is the
/// VM-facing device; `proxy_iface` is the only permitted egress path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressWiring {
    pub vm_id: String,
    pub tap_iface: String,
    pub proxy_iface: String,
}

/// Errors from egress enforcement. Mirrors the host firewall's failure modes
/// so the fail-closed posture survives the seam.
#[derive(Debug)]
pub enum EnforcementError {
    /// No real enforcer is wired (a Noop slot). Fail closed — never boot a VM
    /// with silent host egress.
    NotWired,
    /// The wiring/policy was rejected before any backend apply (e.g. an unsafe
    /// interface name).
    Rejected(String),
    /// The platform backend (nftables, …) failed to apply.
    Backend(String),
}

impl std::fmt::Display for EnforcementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotWired => write!(f, "egress enforcer not wired (fail closed)"),
            Self::Rejected(m) => write!(f, "egress wiring rejected: {m}"),
            Self::Backend(m) => write!(f, "egress enforcement backend failed: {m}"),
        }
    }
}

impl std::error::Error for EnforcementError {}

/// The seam the supervisor's host-egress enforcement sits behind. Object-safe
/// and dependency-light. A [`NetworkProvider`](crate::NetworkProvider) that
/// doesn't self-enforce in `provision` (e.g. the future libkrun gvproxy/passt
/// provider) returns one of these from `egress_enforcer()`, and the supervisor
/// drives it; the Firecracker provider self-enforces (iptables in `provision`)
/// and returns `None`.
pub trait EgressEnforcer: Send + Sync {
    /// Install host-side default-deny enforcement scoped to `wiring`. `policy`
    /// is the admitted egress policy (its `Default` is `deny_all()`); the
    /// firewall layer installs a fixed default-deny regardless, so the
    /// policy's allow-rules are the L4/L7 layer's job — `policy` is
    /// threaded now so that widening doesn't change the signature.
    fn enforce(
        &self,
        wiring: &EgressWiring,
        policy: &NetworkPolicy,
    ) -> Result<(), EnforcementError>;

    /// Remove the VM-scoped enforcement.
    fn withdraw(&self, vm_id: &str) -> Result<(), EnforcementError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopEnforcer;
    impl EgressEnforcer for NoopEnforcer {
        fn enforce(
            &self,
            _wiring: &EgressWiring,
            _policy: &NetworkPolicy,
        ) -> Result<(), EnforcementError> {
            Err(EnforcementError::NotWired)
        }
        fn withdraw(&self, _vm_id: &str) -> Result<(), EnforcementError> {
            Err(EnforcementError::NotWired)
        }
    }

    #[test]
    fn noop_enforcer_fails_closed() {
        let e = NoopEnforcer;
        let wiring = EgressWiring {
            vm_id: "vm".into(),
            tap_iface: "tap0".into(),
            proxy_iface: "eth0".into(),
        };
        assert!(matches!(
            e.enforce(&wiring, &NetworkPolicy::deny_all()),
            Err(EnforcementError::NotWired)
        ));
        assert!(matches!(e.withdraw("vm"), Err(EnforcementError::NotWired)));
    }
}
