//! The `NetworkProvider` trait and its supporting types.

use mvm_core::policy::policies::NetworkPolicy;
use mvm_core::protocol::vm_backend::VmId;

/// Host-side description of the network to provision for a VM.
///
/// `policy` defaults to `NetworkPolicy::default()` — the empty L4 allow-list,
/// which the supervisor's gate reads as **deny-all** (claim 10). Opening
/// egress means adding explicit rules, never flipping a default.
#[derive(Debug, Clone, Default)]
pub struct NetworkSpec {
    pub policy: NetworkPolicy,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_spec_default_policy_is_deny_all() {
        // The empty L4 allow-list is the deny-all encoding (policies.rs):
        // the supervisor gate denies any flow not matched by an explicit rule.
        let spec = NetworkSpec::default();
        assert!(
            spec.policy.l4.is_empty(),
            "default NetworkSpec must carry the deny-all (empty) L4 policy"
        );
        assert_eq!(spec.policy, NetworkPolicy::default());
    }
}
