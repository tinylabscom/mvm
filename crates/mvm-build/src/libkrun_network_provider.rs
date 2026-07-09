//! `LibkrunNetworkProvider` — the mvm-build impl of
//! [`mvm_network::NetworkProvider`] for the libkrun vsock-egress path.
//!
//! Unlike the Firecracker `BridgeTapNetworkProvider`, which owns a host bridge
//! + TAP, this provider owns **no host resource**. A libkrun guest's egress is
//! the host-bound vsock relay served by `mvm-libkrun-supervisor`, not a guest
//! NIC plus a host gateway child process. So `provision` is pure config
//! selection and `teardown` is a no-op.
//!
//! claim-10: the provider advertises the default-deny policy while the
//! supervisor-owned vsock relay remains the single chokepoint.
//!
//! Scope: this provider is still a config producer only. Both the builder path
//! ([`apply_networking_mode`](crate::libkrun_builder)) and the workload base
//! config are already NIC-less; this provider just exposes that posture to the
//! registry.

use mvm_core::network_policy::NetworkPolicy;
use mvm_core::protocol::vm_backend::VmId;
use mvm_network::{NetHandle, NetworkError, NetworkProvider, NetworkSpec};

/// Host opt-in for the transparent-TCP vsock egress path on libkrun (Phase A).
/// Unset ⇒ the host-side raw egress listener is not started. Mirrors the
/// present-and-non-empty env-var convention used elsewhere.
pub fn vsock_egress_opt_in() -> bool {
    std::env::var("MVM_VSOCK_EGRESS")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// libkrun vsock-egress network provider (a config producer; owns no host
/// state — see the module docs).
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

    /// Stable kind string for the NIC-less libkrun path.
    fn transport_kind() -> &'static str {
        "vsock-egress"
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
        // Pure selection: the active libkrun path is always NIC-less and
        // relies on the supervisor-owned vsock egress relay.
        Ok(NetHandle {
            vm: vm.clone(),
            tag: Self::transport_kind().to_string(),
        })
    }

    fn policy(&self) -> &NetworkPolicy {
        &self.default_policy
    }

    fn teardown(&self, _handle: NetHandle) -> Result<(), NetworkError> {
        // No host resource to reap: the gateway child + its unix sockets live
        // inside the supervisor process and Drop on guest exit. Contrast
        // BridgeTapNetworkProvider, which must cleanup_network_policy + destroy
        // the TAP here.
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
    fn provision_tags_handle_with_vsock_egress() {
        let provider = LibkrunNetworkProvider::new();
        let handle = provider
            .provision(&VmId("vm".to_string()), &NetworkSpec::default())
            .unwrap();
        // The tag is the fixed transport kind; no host resource is provisioned,
        // so teardown is a clean no-op.
        assert_eq!(handle.tag, "vsock-egress");
        assert_eq!(handle.vm.0, "vm");
        assert!(provider.teardown(handle).is_ok());
    }

    #[test]
    fn transport_kind_is_stable() {
        assert_eq!(LibkrunNetworkProvider::transport_kind(), "vsock-egress");
    }

    #[test]
    fn kind_is_libkrun_policy_is_deny_all_no_separate_enforcer() {
        let provider = LibkrunNetworkProvider::new();
        assert_eq!(provider.kind(), "libkrun");
        // claim-10: advertised default is deny-all, opening egress is opt-in.
        assert_eq!(*provider.policy(), NetworkPolicy::deny_all());
        // libkrun's chokepoint is the supervisor's in-process gateway-bridge
        // FlowPolicy, not a separate EgressEnforcer object -> None (default).
        assert!(provider.egress_enforcer().is_none());
    }

    #[test]
    fn vsock_egress_opt_in_reads_env() {
        // Guard: this test mutates process env; keep it serial-safe by scoping.
        unsafe { std::env::set_var("MVM_VSOCK_EGRESS", "1") };
        assert!(vsock_egress_opt_in());
        unsafe { std::env::remove_var("MVM_VSOCK_EGRESS") };
        assert!(!vsock_egress_opt_in());
    }
}
