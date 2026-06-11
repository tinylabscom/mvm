//! The `NetworkProvider` trait and its supporting types.

use mvm_core::network_policy::NetworkPolicy;
use mvm_core::protocol::vm_backend::VmId;

use crate::enforcement::EgressEnforcer;

/// Host-side description of the network to provision for a VM.
///
/// `policy` is the per-VM host egress policy the provider enforces (iptables
/// for the TAP/bridge backend; this is the `network_policy::NetworkPolicy`
/// that `apply_network_policy` consumes, *not* the supervisor's L4 bundle).
/// Its `Default` is `deny_all()` — the safe claim-10 posture; opening egress
/// is opt-in. `slot_index` is the VM's network-slot ordinal: the backend
/// derives the per-VM tap device + guest IP from it (`tap{index}`,
/// `172.16.0.{index+2}`).
#[derive(Debug, Clone, Default)]
pub struct NetworkSpec {
    pub policy: NetworkPolicy,
    pub slot_index: u8,
}

/// Opaque teardown handle returned by [`NetworkProvider::provision`].
#[derive(Debug, Clone)]
pub struct NetHandle {
    /// The VM this network belongs to.
    pub vm: VmId,
    /// Provider-private teardown tag (tap device name, gvproxy socket path,
    /// mesh peer id, …) — meaningful only to the provider that minted it.
    pub tag: String,
}

/// Errors from network provisioning / teardown / resolution.
#[derive(Debug)]
pub enum NetworkError {
    Provision(String),
    Teardown(String),
    /// No provider registered for a `NetworkMode`'s kind — fails closed, never
    /// a silent default.
    UnknownProvider {
        kind: String,
    },
}

impl std::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Provision(m) => write!(f, "network provision failed: {m}"),
            Self::Teardown(m) => write!(f, "network teardown failed: {m}"),
            Self::UnknownProvider { kind } => {
                write!(f, "no NetworkProvider registered for mode kind {kind:?}")
            }
        }
    }
}

impl std::error::Error for NetworkError {}

/// Provisioning + policy + teardown for one VM's network.
///
/// Impls: the mvm-backend TAP/bridge/gvproxy/passt provider (per-OS), mvmd's
/// WireGuard/Tailscale mesh provider. The provider hides the per-OS gateway
/// choice (`MVM_NETWORKING`) from callers.
pub trait NetworkProvider: Send + Sync {
    /// Stable kind string — `"bridge"` | `"gvproxy"` | `"passt"` |
    /// `"wireguard"` | … . Matched against a `NetworkMode`'s kind by the
    /// registry.
    fn kind(&self) -> &str;

    /// Bring up `vm`'s network per `spec`, returning a teardown handle.
    fn provision(&self, vm: &VmId, spec: &NetworkSpec) -> Result<NetHandle, NetworkError>;

    /// The enforced policy. Default-deny until explicitly opened (claim 10).
    fn policy(&self) -> &NetworkPolicy;

    /// Tear the VM's network down, consuming its handle.
    fn teardown(&self, handle: NetHandle) -> Result<(), NetworkError>;

    /// The host-egress enforcer this provider drives, if any. `None` (default)
    /// means egress is enforced by a mechanism the provider does not own as a
    /// separate object: the Firecracker `BridgeTapNetworkProvider` self-enforces
    /// iptables inside `provision`, and the libkrun gvproxy/passt provider (L3)
    /// relies on the supervisor's in-process gateway-bridge `FlowPolicy`
    /// chokepoint. A provider returns `Some(..)` only when it drives a distinct
    /// [`EgressEnforcer`] object (the `SupervisorEgressEnforcer`).
    fn egress_enforcer(&self) -> Option<&dyn EgressEnforcer> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_spec_default_policy_is_deny_all() {
        // network_policy::NetworkPolicy::default() is deny_all() — the safe
        // claim-10 posture the provider enforces unless egress is opt-in.
        let spec = NetworkSpec::default();
        assert_eq!(spec.policy, NetworkPolicy::deny_all());
        assert!(!spec.policy.is_unrestricted());
    }
}
