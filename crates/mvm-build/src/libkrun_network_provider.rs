//! `LibkrunNetworkProvider` — the mvm-build impl of
//! [`mvm_net::NetworkProvider`] for the libkrun direct-vsock path.
//!
//! Unlike the Firecracker `BridgeTapNetworkProvider`, which owns a host bridge
//! + TAP, this provider owns **no host resource**. A libkrun guest's runtime
//! control path is the explicit vsock device, wired later inside the
//! supervisor. So `provision` is a pure config statement and `teardown` is a
//! no-op.
//!
//! claim-10: the provider does not choose among guest-NIC helpers. There is
//! one transport and it is vsock.

use mvm_core::network_policy::NetworkPolicy;
use mvm_core::protocol::vm_backend::VmId;
use mvm_net::{NetHandle, NetworkError, NetworkProvider, NetworkSpec};

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

    /// Stable kind string for the libkrun transport. There is exactly one.
    const TRANSPORT_TAG: &'static str = "vsock_direct";
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
        // No host syscalls run here; the explicit vsock device is wired later
        // inside the supervisor.
        Ok(NetHandle {
            vm: vm.clone(),
            tag: Self::TRANSPORT_TAG.to_string(),
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
    use mvm_net::{NetworkProvider, NetworkSpec};

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

    /// The tag a caller reads off the handle is the vsock transport, and
    /// nothing selects any other. Asserted on the provisioned handle rather
    /// than on a constant, so the assertion still covers `provision` wiring.
    #[test]
    fn provisioned_handle_tags_the_vsock_transport() {
        let provider = LibkrunNetworkProvider::new();
        let handle = provider
            .provision(&VmId("vm-tag".into()), &NetworkSpec::default())
            .expect("provision");
        assert_eq!(handle.tag, "vsock_direct");
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
