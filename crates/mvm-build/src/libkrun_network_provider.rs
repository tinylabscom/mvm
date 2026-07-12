//! `LibkrunNetworkProvider` — the mvm-build impl of
//! [`mvm_network::NetworkProvider`] for the libkrun direct-vsock path.
//!
//! Unlike the Firecracker `BridgeTapNetworkProvider`, which owns a host bridge
//! + TAP, this provider owns **no host resource**. A libkrun guest's runtime
//! control path is the explicit vsock device, configured later when the
//! supervisor consumes the resolved [`NetworkingPreference`]. So `provision` is
//! a pure config selection and `teardown` is a no-op.
//!
//! claim-10: the provider no longer chooses among guest-NIC helpers at all.
//! The active contract is vsock-only.
//!
//! Scope: this provider is still a config producer only. Both the builder path
//! ([`apply_networking_mode`](crate::libkrun_builder)) and the workload base
//! config resolve the same [`NetworkingPreference`] helper; re-pointing them
//! through this provider is a cleanup, not a behavior gate.

use mvm_core::network_policy::NetworkPolicy;
use mvm_core::protocol::vm_backend::VmId;
use mvm_network::{NetHandle, NetworkError, NetworkProvider, NetworkSpec};

use crate::libkrun_builder::{NetworkingPreference, resolve_networking_mode};

/// libkrun direct-vsock provider (a config producer; owns no host state — see
/// the module docs).
pub struct LibkrunNetworkProvider {
    /// The provider's advertised default — `deny_all()` (claim 10). The
    /// effective per-VM policy arrives via [`NetworkSpec`] on `provision`.
    default_policy: NetworkPolicy,
}

impl LibkrunNetworkProvider {
    pub fn new() -> Self {
        Self {
            default_policy: NetworkPolicy::deny_all(),
        }
    }

    /// Stable kind string for the resolved libkrun transport.
    fn gateway_kind(pref: NetworkingPreference) -> &'static str {
        match pref {
            NetworkingPreference::VsockDirect => "vsock_direct",
        }
    }
}

impl Default for LibkrunNetworkProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkProvider for LibkrunNetworkProvider {
    fn kind(&self) -> &str {
        "libkrun"
    }

    fn provision(&self, vm: &VmId, _spec: &NetworkSpec) -> Result<NetHandle, NetworkError> {
        // Pure selection: resolve the libkrun transport. No host syscalls run
        // here; the explicit vsock device is wired later inside the supervisor.
        Ok(NetHandle {
            vm: vm.clone(),
            tag: Self::gateway_kind(resolve_networking_mode()).to_string(),
        })
    }

    fn policy(&self) -> &NetworkPolicy {
        &self.default_policy
    }

    fn teardown(&self, _handle: NetHandle) -> Result<(), NetworkError> {
        // No host resource to reap on this path.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::network_policy::NetworkPolicy;
    use mvm_core::protocol::vm_backend::VmId;
    use mvm_network::{NetworkProvider, NetworkSpec};

    #[test]
    fn provision_tags_handle_with_vsock_direct() {
        let provider = LibkrunNetworkProvider::new();
        let handle = provider
            .provision(&VmId("vm".to_string()), &NetworkSpec::default())
            .unwrap();
        assert_eq!(handle.tag, "vsock_direct");
        assert_eq!(handle.vm.0, "vm");
        assert!(provider.teardown(handle).is_ok());
    }

    #[test]
    fn gateway_kind_maps_vsock_direct() {
        assert_eq!(
            LibkrunNetworkProvider::gateway_kind(NetworkingPreference::VsockDirect),
            "vsock_direct"
        );
    }

    #[test]
    fn kind_is_libkrun_policy_is_deny_all_no_separate_enforcer() {
        let provider = LibkrunNetworkProvider::new();
        assert_eq!(provider.kind(), "libkrun");
        // claim-10: advertised default is deny-all, opening egress is opt-in.
        assert_eq!(*provider.policy(), NetworkPolicy::deny_all());
        // This provider is still a pure config producer, not a separate
        // enforcer object.
        assert!(provider.egress_enforcer().is_none());
    }
}
